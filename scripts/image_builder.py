#!/usr/bin/env python3
#
# Generic image builder for Phoenix-RTOS based projects.
# Parses plo scripts in YAML format to produce target plo scripts partition/disk images.
#
# Copyright 2024 Phoenix Systems
# Author: Marek Bialowas
#

import argparse
import logging
import os
import sys
import subprocess
from collections import defaultdict
from enum import Enum, IntEnum
from pathlib import Path
from dataclasses import InitVar, asdict, dataclass, field, KW_ONLY, fields
from typing import IO, Any, BinaryIO, ClassVar, Dict, List, Optional, TextIO, Tuple, Union
import yaml
import jinja2

from nvm_config import FlashMemory, read_nvm, find_target_part
from strip import ElfParser, PhFlags, PhType

VERSION = (1, 0, 0)


# global consts (taken from env/commandline)
TARGET: str
SIZE_PAGE: int
PREFIX_BOOT: Path
PREFIX_ROOTFS: Path
PREFIX_PROG_STRIPPED: Path
PLO_SCRIPT_DIR: Path


@dataclass
class ProgInfo:
    path: Path
    offs: int
    size: int
    max_size: int = 0  # if != 0 -> we have dest restriction about size, check/report it!

    def __post_init__(self):
        if self.max_size != 0:
            if self.size > self.max_size:
                raise ValueError(f"{str(self.path)} size: {self.size} exceeds max_size {self.max_size}")

    def __str__(self) -> str:
        if self.max_size != 0:
            size_str = f"size={self.size:#8x} / {self.max_size:#8x} {100 * self.size // self.max_size}%"
        else:
            size_str = f"size={self.size:#8x}"
        return f"{str(self.path.name):30s} (offs={self.offs:#10x}, {size_str})"


def round_up(size: int, size_page: int) -> int:
    return (size + size_page - 1) & ~(size_page - 1)


def get_elf_sizes(path : Path) -> Tuple[int, int, int, int]:
    """Returns vaddr + ceil(mem_size, SIZE_PAGE) of TEXT and BSS sections"""

    with open(path, "rb") as f:
        elf = ElfParser(f)
        logging.debug(elf.get_program_headers())

        text_ph = []
        bss_ph = []

        for ph, _ in elf.get_program_headers():
            if ph.p_type == PhType.PT_LOAD:
                if ph.p_flags == PhFlags.PF_R | PhFlags.PF_X:
                    text_ph.append(ph)

                if ph.p_flags == PhFlags.PF_R | PhFlags.PF_W:
                    bss_ph.append(ph)

        assert len(text_ph) == 1
        assert len(bss_ph) == 1

        return (text_ph[0].p_vaddr, round_up(text_ph[0].p_memsz, SIZE_PAGE),
                bss_ph[0].p_vaddr, round_up(bss_ph[0].p_memsz, SIZE_PAGE))


class PloScriptEncoding(Enum):
    """All supported types of PLO script encoding"""
    DEBUG_ASDICT = -1    # debug-only output
    STRING_MAGIC_V1 = 0  # human-readable string, beginning with 8-char magic string
    # BINARY_V1 = 10        # packed binary representation of the script NOTE: not yet implemented


class PloCmdFactory:
    """Plo command factory from different input args/kwargs"""

    @staticmethod
    def _extract_extra_flags(cmd_args: List[str]) -> Optional[str]:
        """Deletes from cmd_args and returns first param beginning with '-'"""
        for arg in cmd_args:
            if arg.startswith('-'):
                cmd_args.remove(arg)
                return arg

        return None

    @classmethod
    def build(cls, cmd: str = "", **kwargs):
        cmd_args = []
        if "name" in kwargs:
            cmd_name = kwargs.pop("name")
        elif "action" in kwargs:
            cmd_name = kwargs.pop("action")
        else:  # command as a string
            cmd_name, *cmd_args = cmd.split()

        if not cmd_name:
            raise ValueError(f"unknown CMD format: str='{cmd}', kwargs={kwargs}")

        kwargs["name"] = cmd_name
        extra_flags = cls._extract_extra_flags(cmd_args)
        # set extra_flags only if not explicitly provided
        if extra_flags is not None:
            kwargs["extra_flags"] = kwargs.get("extra_flags", extra_flags)

        # TODO: use more generic approach with cls.NAME?
        if cmd_name in ("kernel", "kernelimg"):
            return PloCmdKernel(*cmd_args, **kwargs)
        if cmd_name in ("app", "blob"):
            return PloCmdApp(*cmd_args, **kwargs)
        if cmd_name in ("call"):
            return PloCmdCall(*cmd_args, **kwargs)

        # TODO: add compile-time checks for scripts validity (eg. memory regions cross-check)?

        # allow passing commands directly without parsing them by using `%` prefix
        if cmd.startswith("%"):
            return PloCmdGeneric(cmd[1:].strip())

        # generic PLO command - treated for now as string
        return PloCmdGeneric(cmd)


@dataclass
class PloCmdBase:
    """Base class for all PLO commands"""
    NAME: ClassVar[str] = "unknown"
    name: str = field(default=NAME, kw_only=True)
    # command extra flags (first param from string beginning with '-')
    extra_flags: InitVar[str] = field(default='', kw_only=True)

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, Optional[ProgInfo]]:
        """
        Emit plo command into `file` using `enc` encoding.

        Args:
            payload_offs: Current offset in partition file
            is_relative:  True if the current script should use relative aliases (alias -b needs to be called in one of the previous scripts)

        Returns:
            Tuple (new payload_offs and optional ProgInfo if data needs to be added to the partition file)
        """

        raise NotImplementedError(f"{self.__class__.__name__}: emit not implemented!")


@dataclass
class PloCmdGeneric(PloCmdBase):
    """Generic PLO command - treated only as a string - fallback for unknown specific PLO cmd type"""
    cmd: str

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, Optional[ProgInfo]]:
        if enc == PloScriptEncoding.DEBUG_ASDICT:
            file.write(str(asdict(self)) + "\n")
        elif enc == PloScriptEncoding.STRING_MAGIC_V1:
            # basic plo cmd - just emit as a string
            file.write(self.cmd + "\n")
        else:
            raise NotImplementedError(f"PloScriptEncoding {enc.value} not implemented")

        return payload_offs, None


@dataclass
class PloCmdAlias(PloCmdBase):
    """Alias command - used for memory aliases - emitted usually by app/kernel/blob/call commands"""
    NAME: ClassVar = "alias"
    name: str = field(default=NAME, kw_only=True)

    filename: str               # target alias filename
    size: int                   # target alias size
    set_base: bool = False      # should we set new base before aliasing?

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, ProgInfo]:
        if enc == PloScriptEncoding.DEBUG_ASDICT:
            file.write(str(asdict(self)) + "\n")
        elif enc == PloScriptEncoding.STRING_MAGIC_V1:
            if self.set_base:
                if is_relative:
                    file.write(f"alias -rb {payload_offs:#x}\n")

                    # TODO: add real support for virtual base change (payload_offs in partition, virtual_offs as relative alias)
                    # for now we'll just reset payload_offs - any relative `app` after base change in the same script would break
                    payload_offs = 0
                else:
                    file.write(f"alias -b {payload_offs:#x}\n")

            aliasCmd = "alias -r" if is_relative else "alias"
            file.write(f"{aliasCmd} {self.filename} {payload_offs:#x} {self.size:#x}\n")
        else:
            raise NotImplementedError(f"PloScriptEncoding {enc.value} not implemented")

        return payload_offs + round_up(self.size, SIZE_PAGE), ProgInfo(PREFIX_PROG_STRIPPED / self.filename, payload_offs, self.size)


@dataclass
class PloCmdKernel(PloCmdBase):
    """Kernel is a special type of 'app' due to kernelimg command subtype:
        kernel[img] <device>
        kernel flash0
    """
    NAME: ClassVar = "kernel"
    device: str

    # internal fields
    suffix: str = field(default="elf", init=False)
    size: int = field(init=False)
    filename: str = field(init=False)
    abspath: Path = field(init=False)

    def __post_init__(self, extra_flags: str = ''):
        if self.name == "kernelimg":
            self.suffix = "bin"

        self.filename = f"phoenix-{'-'.join(TARGET.split('-')[:2])}.{self.suffix}"
        self.abspath = PREFIX_PROG_STRIPPED / self.filename
        self.size = os.path.getsize(self.abspath)

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, Optional[ProgInfo]]:
        alias = PloCmdAlias(self.filename, self.size)
        new_offs, prog_info = alias.emit(file, enc, payload_offs, is_relative)

        if enc == PloScriptEncoding.DEBUG_ASDICT:
            file.write(str(asdict(self)) + "\n")
        elif enc == PloScriptEncoding.STRING_MAGIC_V1:
            if self.name == "kernel":
                file.write(f"{self.name} {self.device}\n")
            else:  # kernelimg
                tbeg, tsz, dbeg, dsz = get_elf_sizes(self.abspath.with_suffix(".elf"))
                file.write(f"{self.name} {self.device} {self.filename} {tbeg:#x} {tsz:#x} {dbeg:#x} {dsz:#x}\n")
        else:
            raise NotImplementedError(f"PloScriptEncoding {enc.value} not implemented")

        return new_offs, prog_info


class CmdAppFlags(IntEnum):
    """extra flags for `app` command"""
    # NOTE: they are not flags actually as you can't use `-n` only
    NONE = 0
    EXEC = 1
    EXEC_NO_COPY = 2

    def emit_as_string(self) -> str:
        if self.value == CmdAppFlags.EXEC:
            return " -x"
        if self.value == CmdAppFlags.EXEC_NO_COPY:
            return " -xn"
        return ""

    @classmethod
    def _missing_(cls, value):
        """Makes it possible to initialize class from name-as-a-string"""
        if isinstance(value, str):
            value = value.upper()
            if value in dir(cls):
                return cls[value]

        raise ValueError(f"{value} is not a valid {cls.__name__}")


@dataclass
class PloCmdApp(PloCmdBase):
    """Support for app/blob command:
        app <device> [-x|-xn] <filename[;args]> <text_map> <data_map[;extra_maps]>
        blob <device> </rootfs/path> <data_map>
        app flash0 -x psh;-i;/etc/rc.psh ddr ddr
    """
    NAME: ClassVar = "app"
    name: str = field(default=NAME, kw_only=True)

    device: str                         # PLO device name
    filename_args: InitVar[str] = ""    # program/blob name/full path with optional args separated by `;`
    text_map: str = ""                  # target memory map for program .text
    data_maps: str = ""                 # target memory map for program data + extra maps the process should have access to
    _ = KW_ONLY
    filename: str = ""
    args: List[str] = field(default_factory=list)
    flags: CmdAppFlags | str | int = CmdAppFlags.NONE

    # internal fields
    size: int = field(init=False)
    abspath: Path = field(init=False)

    @staticmethod
    def _resolve_filename(filename: str) -> Tuple[str, Path]:
        if filename.startswith("/"):
            return os.path.basename(filename), PREFIX_ROOTFS / filename.lstrip("/")

        return filename, PREFIX_PROG_STRIPPED / filename

    def _parse_flags(self, extra_flags: str):
        # flags attr takes precedence
        if self.flags and isinstance(self.flags, str):
            self.flags = CmdAppFlags(self.flags)
            return

        if extra_flags == "-x":
            self.flags = CmdAppFlags.EXEC
        elif extra_flags == "-xn":
            self.flags = CmdAppFlags.EXEC_NO_COPY

    def __post_init__(self, extra_flags: str = '', filename_args: str = ''):
        self._parse_flags(extra_flags)

        if filename_args:
            self.filename, *self.args = filename_args.split(";", maxsplit=1)

        if isinstance(self.args, str):
            self.args = self.args.split(";")

        # remove empty strings from self.args (easier handling of jinja2 conditional params)
        self.args = list(filter(None, self.args))

        # filename can be either relative to PROG_STRIPPED or absolute (in ROOTFS)
        self.filename, self.abspath = self._resolve_filename(self.filename)

        self.size = os.path.getsize(self.abspath)

        # HACKISH: blob cmd - treat 'text_map' as data map to support specifying by string
        if self.name == "blob" and not self.data_maps and self.text_map:
            self.data_maps = self.text_map
            self.text_map = ""

        required_attrs = ["filename", "data_maps"]
        if self.name == "app":
            required_attrs.append("text_map")

        for req_val_name in required_attrs:
            if not asdict(self).get(req_val_name):
                raise TypeError(f"Required attribute '{req_val_name}' not present/empty")

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, Optional[ProgInfo]]:
        alias = PloCmdAlias(self.filename, self.size)
        new_offs, prog_info = alias.emit(file, enc, payload_offs, is_relative)
        prog_info.path = self.abspath

        if enc == PloScriptEncoding.DEBUG_ASDICT:
            file.write(str(asdict(self)) + "\n")
        elif enc == PloScriptEncoding.STRING_MAGIC_V1:
            maps_str = f"{self.text_map} {self.data_maps}".strip()  # remove extra spaces if `text_map` is not used (blob cmd)
            file.write(f"{self.name} {self.device}{self.flags.emit_as_string()} "
                       f"{';'.join([self.filename, *self.args])} {maps_str}\n")
        else:
            raise NotImplementedError(f"PloScriptEncoding {enc.value} not implemented")

        return new_offs, prog_info


@dataclass
class PloCmdCall(PloCmdBase):
    """Support for call command:
        call [-setbase|-absolute] <device> <alias_name> <target_offs> <target_magic>
        call flash0 nlr0.plo 0x400000 0xdabaabad
    """
    NAME: ClassVar = "call"
    device: str                 # PLO device name
    filename: str               # target script (alias) filename
    offset: int                 # target script offset (absolute or relative)
    target_magic: str | None    # target script magic if used
    set_base: bool = False      # should we set new base before calling the script?
    absolute: bool = False      # should we force absolute call even if the current script is relative?
    name: str = field(default=NAME, kw_only=True)

    # internal fields
    size: int = field(init=False)

    def __post_init__(self, extra_flags: str = ''):

        if extra_flags == "-setbase":
            self.set_base = True
        if extra_flags == "-absolute":
            self.absolute = True

        # change str->desired type TODO: use decorators?
        if isinstance(self.offset, str):
            self.offset = int(self.offset, 0)

        self.size = 0x1000  # FIXME: get real defined script size

    def emit(self, file: TextIO, enc: PloScriptEncoding, payload_offs: int, is_relative: bool) -> Tuple[int, Optional[ProgInfo]]:
        alias = PloCmdAlias(self.filename, self.size, set_base=self.set_base)
        if self.absolute:  # force absolute call even if the current script is relative
            is_relative = False

        alias.emit(file, enc, self.offset, is_relative)

        if enc == PloScriptEncoding.DEBUG_ASDICT:
            file.write(str(asdict(self)) + "\n")
        elif enc == PloScriptEncoding.STRING_MAGIC_V1:
            file.write(f"call {self.device} {self.filename} {self.target_magic}\n")
        else:
            raise NotImplementedError(f"PloScriptEncoding {enc.value} not implemented")

        # call doesn't change the payload offset nor write anything to the target partition
        return payload_offs, None


@dataclass
class PloScript:
    """Full PLO script definition"""
    size: int                  # reserved size for the plo script
    offs: int = 0              # script offset from the beginning of flash (if not relative) or 0 (if relative)
    is_relative: bool = False  # if relative, all aliases start from offset `0`, otherwise they start from offset `offs`
    magic: str | None = None   # PLO script magic
    contents: List[PloCmdBase] = field(default_factory=list, init=False)

    def __post_init__(self):
        # fix types
        if isinstance(self.size, str):
            self.size = int(self.size)
        if isinstance(self.offs, str):
            self.offs = int(self.offs)

    def write(self, file: TextIO, enc: PloScriptEncoding = PloScriptEncoding.STRING_MAGIC_V1) -> List[ProgInfo]:
        prog_offs = self.offs + self.size  # init with "just after the script"
        progs = []

        if self.magic is not None:
            if len(self.magic) != 8:
                raise ValueError(f"PLO magic string '{self.magic}' with invalid len ({len(self.magic)} != 8)")
            file.write(f"{self.magic}\n")
        for cmd in self.contents:
            prog_offs, prog_spec = cmd.emit(file, enc, prog_offs, self.is_relative)
            if prog_spec:
                progs.append(prog_spec)

        file.write("\0")

        if file.tell() > self.size:
            raise ValueError(f"Generated user script is too large (allocated size: {self.size} < actual size {file.tell()})")

        return progs


def render_val(tpl: Any, **kwargs) -> Any:  # mostly str | List[str] | Dict[str, str]
    """Uses jinja2 to render possible template variable - kwargs will be defined global variables"""

    # use recurrence for collections
    if isinstance(tpl, list):
        return [render_val(item, **kwargs) for item in tpl]
    if isinstance(tpl, dict):
        return {k: render_val(v, **kwargs) for k, v in tpl.items()}

    if isinstance(tpl, str):
        rendered = jinja2.Template(tpl, undefined=jinja2.StrictUndefined).render(env=os.environ, **kwargs)
        if tpl!= rendered:
            logging.debug("render_val: '%s' -> '%s'", tpl, rendered)
        return rendered

    # shortcut for lazy callers - return value with original type
    return tpl


def str2bool(v: str | bool) -> bool:
    """False is denoted by empty string or any literal sensible false values"""
    if isinstance(v, bool):
        return v
    return v.lower() not in ("", "no", "false", "n", "0")


def nvm_to_dict(nvm: List[FlashMemory]) -> Dict[str, Dict[str, Any]]:
    """Convert NVM to basic data types for jinja2 templates resolution"""
    nvm_dict = {f.name: {p.name: p for p in f.parts} for f in nvm}
    for flash in nvm:
        nvm_dict[flash.name]['_meta'] = {f.name: getattr(flash, f.name) for f in fields(flash)}

    return nvm_dict


def parse_plo_script(nvm: List[FlashMemory], script_name: str) -> PloScript:
    """Parse YAML/jinja2 plo script and return it as PloScript object"""

    nvm_dict = nvm_to_dict(nvm)

    with open(script_name, "r", encoding="utf-8") as f:
        script_dict = yaml.safe_load(f)

        # render templates in basic plo script attributes
        plo_param_names = [f.name for f in fields(PloScript) if f.init]
        plo_kwargs = {k: render_val(script_dict.get(k), nvm=nvm_dict) for k in plo_param_names if k in script_dict}
        script = PloScript(**plo_kwargs)

        tpl_context = {'nvm': nvm_dict, 'script': script}
        for cmd in script_dict['contents']:
            try:
                if isinstance(cmd, str):
                    cmd_rendered = render_val(cmd, **tpl_context)
                    cmddef = PloCmdFactory.build(cmd_rendered)
                else:
                    # render all values
                    args = {k: render_val(v, **tpl_context) for k, v in cmd.items()}
                    enabled = args.pop('if', True)
                    if not str2bool(enabled):
                        logging.debug("PLO command disabled (if: '%s'): %s", enabled, str(args))
                        continue

                    if 'str' in args:
                        # command still as string, just conditional
                        cmddef = PloCmdFactory.build(args["str"])
                    else:
                        # treat all dict elements as keyword arguments
                        cmddef = PloCmdFactory.build(**args)

                script.contents.append(cmddef)
            except Exception as ex:
                raise ValueError(f"Failed to parse PLO CMD: {cmd}") from ex

        return script


def write_plo_script(nvm: List[FlashMemory],
                     script_name:
                     str, out_name: str | None = None,
                     enc: PloScriptEncoding = PloScriptEncoding.STRING_MAGIC_V1) -> List[ProgInfo]:
    """Write desired PLO script and return contents of the target partition (including plo script itself)"""
    os.makedirs(PLO_SCRIPT_DIR, exist_ok=True)
    plo_script = parse_plo_script(nvm, script_name)

    if out_name is not None:
        if out_name.startswith("/"):
            path = Path(out_name)
        else:
            path = PLO_SCRIPT_DIR / out_name
    else:
        path = PLO_SCRIPT_DIR / os.path.basename(script_name).removesuffix(".yaml")

    with open(path, "w", encoding="ascii") as f:
        progs = plo_script.write(f, enc)

    progs = [ProgInfo(path, plo_script.offs, os.path.getsize(path), max_size=plo_script.size)] + progs
    return progs



def set_offset(file: IO[bytes], target_offset: int, padding_byte: int):
    """Sets the file position to `target_offset` - write `padding_byte` to extend the file if necessary"""
    assert 0 <= padding_byte <= 255
    CHUNK_SIZE = 512

    # always move to the end of the file (previous write might have been in the middle)
    file.seek(0, os.SEEK_END)
    curr_offset = file.tell()

    if (diff := target_offset - curr_offset) > 0:

        full, part = (diff // CHUNK_SIZE, diff % CHUNK_SIZE)
        pad_chunk = bytes([padding_byte]) * CHUNK_SIZE
        file.write(pad_chunk[:part])
        for _ in range(full):
            file.write(pad_chunk)
    elif target_offset != curr_offset:  # overwriting parts of the existing image - just set the position directly
        file.seek(target_offset)

    assert file.tell() == target_offset, f"{file.tell()} != {target_offset}"


def add_to_image(fout: BinaryIO, offset: int, fpath: Union[str, Path], padding_byte: int):
    """Add file data (`fpath`) to the target image file (`fout`) at a given `offset`"""
    set_offset(fout, offset, padding_byte)

    CHUNK_SIZE = 512
    written = 0
    with open(fpath, "rb") as fin:
        while True:
            data = fin.read(CHUNK_SIZE)
            written += fout.write(data)
            if len(data) != CHUNK_SIZE:
                break

    return written


def remove_if_exists(path: Path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def create_ptable(flash: FlashMemory) -> Path:
    tool = PREFIX_BOOT / "psdisk"
    out_fn = PREFIX_BOOT / flash.ptable_filename
    remove_if_exists(out_fn)

    cmd: List[str] = [str(tool), str(out_fn), "-m", f"0x{flash.size:x},0x{flash.block_size:x}"]
    for part in flash.parts:
        if part.virtual:
            continue
        cmd.extend(("-p", f"{part.name},0x{part.offs:x},0x{part.size:x},0x{part.type.value:x}"))

    logging.debug("command: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, check=True)
    logging.info(proc.stdout.decode())

    return out_fn


def write_image(contents: List[ProgInfo], img_out_name: Path, img_max_size: int, padding_byte) -> int:
    """Creates partition/disk image with desired `contents`"""
    remove_if_exists(img_out_name)

    logging.verbose("program images:\n%s", "\n".join([str(prog) for prog in contents]))

    if not contents:
        raise ValueError("Empty partition definition")

    with open(img_out_name, "wb") as fout:
        for prog in contents:
            written = add_to_image(fout, prog.offs, prog.path, padding_byte)
            assert written == prog.size, f"{prog.path}: write failed: written={written}, size={prog.size}"

    img_size = os.path.getsize(img_out_name)
    logging.info("Created %-20s with size %8u / %8u (%4u kB  %3u %%)", os.path.basename(img_out_name),
                 img_size, img_max_size, img_size / 1024, 100 * img_size // img_max_size)

    assert img_size <= img_max_size, f"Partition image exceeds total size {img_size} > {img_max_size}"
    return 0


def parse_args() ->argparse.Namespace:
    def env_or_required(key):
        """required as a commandline param or ENV var"""
        return {'default': os.environ.get(key)} if key in os.environ else {'required': True}

    parser = argparse.ArgumentParser(description="Create PLO scripts, partitions and disk images")
    parser.add_argument("-v", "--verbose", action='count', default=0, help="Increase verbosity (can be used multiple times)")
    parser.add_argument("--version", action="version", version=f"{parser.prog} {VERSION[0]}.{VERSION[1]}.{VERSION[2]}")

    # common paths - usually taken from build via env
    parser.add_argument("--target", **env_or_required("TARGET"), help="TARGET identification string")
    parser.add_argument("--size-page", **env_or_required("SIZE_PAGE"), type=int, help="Target page size")
    parser.add_argument("--prefix-boot", **env_or_required("PREFIX_BOOT"), help="boot directory path")
    parser.add_argument("--prefix-rootfs", **env_or_required("PREFIX_ROOTFS"), help="boot directory path")
    parser.add_argument("--prefix-prog-stripped", **env_or_required("PREFIX_PROG_STRIPPED"), help="prog.stripped directory path")
    parser.add_argument("--plo-script-dir", **env_or_required("PLO_SCRIPT_DIR"), help="output PLO scripts directory path")

    subparsers = parser.add_subparsers(help="subcommands", dest="cmd")
    ptable = subparsers.add_parser("ptable", help="prepare partition tables")
    ptable.add_argument("--nvm", type=str, default="nvm.yaml", help="Path to NVM config (default: %(default)s)")

    query = subparsers.add_parser("query", help="Render jinja2 template")
    query.add_argument("--nvm", type=str, default="nvm.yaml", help="Path to NVM config (default: %(default)s)")
    query.add_argument("query", type=str, help="Template to render")


    partition = subparsers.add_parser("partition", aliases=["part"], help="prepare partition image")

    # opt 1 - use NVM config + part name
    partition.add_argument("--nvm", type=str, default="nvm.yaml", help="Path to NVM config (default: %(default)s)")
    partition.add_argument("--name", type=str, dest="part_name", help="Partition name from NVM in format [flash_name:]part_name")
    # TODO: opt 2 - provide partition details by hand?

    part_exclusive_group = partition.add_mutually_exclusive_group(required=True)
    # opt 1 - use PLO script for partition definition
    part_exclusive_group.add_argument("--script", type=str, dest="script_name", help="YAML PLO script definition")
    # opt 2 - define partition contents by hand
    part_exclusive_group.add_argument("--contents", type=str, action="append", help="filename to append to the partition image in format `path[:offset]`")


    script = subparsers.add_parser("script", help="prepare PLO script from yaml/template")
    script.add_argument("--nvm", type=str, default="nvm.yaml", help="Path to NVM config (default: %(default)s)")
    script.add_argument("--script", type=str, required=True, dest="script_name", help="YAML PLO script definition")
    script.add_argument("--out", type=str, dest="out_name", help="Output script name (or full path) - default is the script name without .yaml suffix")


    disk = subparsers.add_parser("disk", help="prepare disk image")
    disk.add_argument("--nvm", type=str, default="nvm.yaml", help="Path to NVM config (default: %(default)s)\nBy default all partition image files will be used.")
    disk.add_argument("--name", type=str, dest="flash_name", help="Flash name from NVM")
    disk.add_argument("--part", type=str, action="append", help="Custom partition mapping in format [flash_name:]part_name=img_path")
    disk.add_argument("--out", type=str, dest="out_name", help="Output disk file name (or full path) - default is the name from nvm config")

    args = parser.parse_args()

    # set common paths/vars as globals
    global TARGET, SIZE_PAGE, PREFIX_BOOT, PREFIX_ROOTFS, PREFIX_PROG_STRIPPED, PLO_SCRIPT_DIR
    TARGET = args.target
    SIZE_PAGE = args.size_page
    PREFIX_BOOT = Path(args.prefix_boot)
    PREFIX_ROOTFS = Path(args.prefix_rootfs)
    PREFIX_PROG_STRIPPED = Path(args.prefix_prog_stripped)
    PLO_SCRIPT_DIR = Path(args.plo_script_dir)

    return args


VERBOSE = 15


def main() -> int:
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
    logging.addLevelName(VERBOSE, 'VERBOSE')
    # HACKISH: add function to the module for verbose logging
    logging.verbose = lambda msg, *args, **kwargs: logging.log(VERBOSE, msg, *args, **kwargs)

    args = parse_args()

    if args.verbose > 0:
        logging.getLogger().setLevel(logging.DEBUG if args.verbose == 2 else VERBOSE)


    nvm: List[FlashMemory] = []
    if args.nvm:
        nvm = read_nvm(args.nvm)

    if args.cmd == "ptable":
        for flash in nvm:
            ptable_path = create_ptable(flash)

            # prepare ptable partition image
            ptable_part = find_target_part(nvm, f"{flash.name}:ptable")
            if not ptable_part:
                raise ValueError(f"No ptable partition defined for flash {flash.name}")

            ptable_size = os.path.getsize(ptable_path)
            progs = []
            for offs in range(0, ptable_part.size, flash.block_size):
                progs.append(ProgInfo(ptable_path, offs, ptable_size))

            write_image(progs, PREFIX_BOOT / ptable_part.filename, ptable_part.size, ptable_part.flash.padding_byte)

        # errors during ptable creation will raise an exception with problem description
        return 0

    if args.cmd == "query":
        nvm_dict = nvm_to_dict(nvm)
        print(render_val(args.query, nvm=nvm_dict))
        return 0

    if args.cmd == "script":
        #TODO: update the result file only if different (avoid unnecessary re-linking plo with every build)
        progs = write_plo_script(nvm, args.script_name, args.out_name)
        out_script = progs[0]
        logging.info("PLO script written to %s (size=%u)", out_script.path, os.path.getsize(out_script.path))
        logging.debug("program images:\n%s", "\n".join([str(prog) for prog in progs]))
        return 0

    if args.cmd in ("part", "partition"):
        target_part = find_target_part(nvm, args.part_name)
        if not target_part:
            raise ValueError("Can't find target partition with given params")

        contents: List[ProgInfo] = []
        if args.script_name:
            contents = write_plo_script(nvm, args.script_name)

            # if we're making non-relative plo script - change offsets by partition beginning
            if contents and (contents[0].offs - target_part.offs) >= 0:
                for prog in contents:
                    prog.offs -= target_part.offs

        elif args.contents:
            curr_offs = 0
            for name in args.contents:
                if ":" in name:
                    name, offs = name.split(":")
                    assert int(offs) >= curr_offs, f"offset {offs} larger than current offset ({curr_offs})"
                    curr_offs = int(offs)

                contents.append(ProgInfo(Path(name), curr_offs, os.path.getsize(name)))

        return write_image(contents, PREFIX_BOOT / target_part.filename, target_part.size, target_part.flash.padding_byte)

    if args.cmd == "disk":
        # support `--part` overrides in format: `[flash_name:]part_name=img_path`
        overrides: Dict[str, Dict[str, str]] = defaultdict(dict)
        if args.part:
            for pdef in args.part:
                part_name, img_path = pdef.split("=")
                part = find_target_part(nvm, part_name)
                if part is None:
                    raise KeyError(f"Unknown partition definition: {part_name}")
                overrides[part.flash.name][part.name] = img_path

        at_least_one_image_created = False
        for flash in nvm:
            if args.flash_name and flash.name != args.flash_name:
                continue

            progs: List[ProgInfo] = []
            for part in flash.parts:
                if part.empty:  # never try to write the file
                    continue
                if part.name in overrides[flash.name]:
                    part_img = overrides[flash.name][part.name]
                    if part_img.lower() in ("none", "null"):
                        continue
                    if not part_img.startswith("/"):
                        part_img = PREFIX_BOOT / part_img
                    else:
                        part_img = Path(part_img)
                else:
                    part_img = PREFIX_BOOT / part.filename

                # for virtual ranges: allow explicit writing, missing partition is not an error
                if part.virtual and not os.path.exists(part_img):
                    continue

                progs.append(ProgInfo(part_img, part.offs, os.path.getsize(part_img), max_size=part.size))

            disk_path = PREFIX_BOOT / f"{flash.name}.disk"
            if args.out_name:
                disk_path = Path(args.out_name) if args.out_name.startswith('/') else PREFIX_BOOT / args.out_name
            write_image(progs, disk_path, flash.size, flash.padding_byte)
            at_least_one_image_created = True

        if not at_least_one_image_created:
            raise ValueError(f"No disk image created - check `name` param ('{args.flash_name}') and NVM config!")

        return 0

    return 1 # unknown command


if __name__ == "__main__":
    sys.exit(main())
