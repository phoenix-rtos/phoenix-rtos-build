#
# Phoenix-RTOS syspage built on host.
#
# syspage_t (phoenix-rtos-kernel include/syspage.h) consists of:
#  - HAL part (`hs`, hal_syspage_t from include/arch/<arch>/<subarch>/syspage.h) - mostly runtime data (boot reason,
#    MPU regions, ...), so plo fills it in on the device,
#  - common part (header fields, memory maps, programs) - target independent.
# The HAL part is built on host only for targets booting the kernel without plo (PLOLESS_TARGETS).
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, ClassVar, Dict, Iterable, List, Optional, Tuple
from imx_hab_defs import ImxIvt, ImxBootData

MAP_ATTRS = {"r": 0x01, "w": 0x02, "x": 0x04, "s": 0x08, "c": 0x10, "b": 0x20}
ALIGN = 8


def align(size: int) -> int:
    return (size + ALIGN - 1) & ~(ALIGN - 1)


def parse_map_attrs(attrs: str) -> int:
    try:
        return sum(MAP_ATTRS[a] for a in set(attrs))
    except KeyError as ex:
        raise ValueError(f"invalid map attribute {ex} in '{attrs}'") from ex


def parse_console(console: str) -> int:
    """`major.minor` -> minor (as syspagen does)"""
    major, sep, minor = console.partition(".")
    if not sep:
        raise ValueError(f"invalid console '{console}' (expected major.minor)")
    int(major, 0)
    return int(minor, 0)


@dataclass
class SyspageMap:
    name: str
    start: int
    end: int
    attr: int


@dataclass
class SyspageProg:
    argv: str          # `name[;arg1;arg2...]`
    start: int         # physical address of the program image
    end: int
    imaps: List[str]   # memory maps names (first one for .text)
    dmaps: List[str]   # memory maps names (first one for data)
    exec: bool = True  # start the program by the kernel


@dataclass
class Syspage:
    """Common part of syspage_t with 32-bit pointers, allocated as in plo/syspagen: 8-byte aligned, in the order of
    commands"""
    console: int = 0
    maps: List[SyspageMap] = field(default_factory=list)
    progs: List[SyspageProg] = field(default_factory=list)

    HDR: ClassVar = struct.Struct("<IIIII")        # size, pkernel, maps, progs, console
    MAP: ClassVar = struct.Struct("<IIIIIIBI")     # next, prev, entries, start, end, attr, id, name
    PROG: ClassVar = struct.Struct("<IIIIIIIII")   # next, prev, start, end, argv, imapSz, imaps, dmapSz, dmaps

    def add_map(self, name: str, start: int, end: int, attrs: str) -> None:
        for m in self.maps:
            if m.name == name or (m.start < end and m.end > start):
                raise ValueError(f"map '{name}' overlaps (or has the same name as) map '{m.name}'")
        self.maps.append(SyspageMap(name, start, end, parse_map_attrs(attrs)))

    def add_prog(self, prog: SyspageProg) -> None:
        names = [m.name for m in self.maps]
        for name in prog.imaps + prog.dmaps:
            if name not in names:
                raise ValueError(f"{prog.argv}: unknown map '{name}'")
        self.progs.append(prog)

    def get_map(self, name: str) -> SyspageMap:
        for m in self.maps:
            if m.name == name:
                return m
        raise ValueError(f"unknown map '{name}'")

    def pack(self, addr: int, hal_size: int, pkernel: int) -> bytes:
        """Common part for the syspage placed at physical address `addr`, following `hal_size` bytes of the HAL part"""
        size = align(hal_size + self.HDR.size)

        def alloc(sz: int) -> int:
            nonlocal size
            offs, size = size, align(size + sz)
            return offs

        map_offs = [(alloc(self.MAP.size), alloc(len(m.name) + 1)) for m in self.maps]
        prog_offs = [(alloc(self.PROG.size), alloc(len(p.dmaps)), alloc(len(p.imaps)), alloc(p.exec + len(p.argv) + 1))
                     for p in self.progs]

        buf = bytearray(size)
        ptr = [addr + offs for offs, _ in map_offs]
        for i, (m, (offs, name)) in enumerate(zip(self.maps, map_offs)):
            self.MAP.pack_into(buf, offs, ptr[(i + 1) % len(ptr)], ptr[i - 1], 0, m.start, m.end, m.attr, i,
                               addr + name)
            buf[name:name + len(m.name)] = m.name.encode("ascii")

        map_ids = {m.name: i for i, m in enumerate(self.maps)}
        prog_ptr = [addr + offs for offs, *_ in prog_offs]
        for i, (p, (offs, dmaps, imaps, argv)) in enumerate(zip(self.progs, prog_offs)):
            self.PROG.pack_into(buf, offs, prog_ptr[(i + 1) % len(prog_ptr)], prog_ptr[i - 1], p.start, p.end,
                                addr + argv, len(p.imaps), addr + imaps, len(p.dmaps), addr + dmaps)
            buf[dmaps:dmaps + len(p.dmaps)] = bytes(map_ids[n] for n in p.dmaps)
            buf[imaps:imaps + len(p.imaps)] = bytes(map_ids[n] for n in p.imaps)
            text = ("X" if p.exec else "") + p.argv
            buf[argv:argv + len(text)] = text.encode("ascii")

        self.HDR.pack_into(buf, hal_size, size, pkernel, ptr[0] if ptr else 0, prog_ptr[0] if prog_ptr else 0,
                           self.console)
        return bytes(buf[hal_size:])


# plo-less boot: HAL part built on host

class HalPart:
    HAL_SYSPAGE_SIZE: ClassVar[int]
    "Size of hal_syspage_t structure for a given platform"
    SYMBOLS: ClassVar[Iterable[str]]
    "Symbols that will be read from the ELF file so that post-processing can use them"

    def pack(self, *, image_size: int) -> bytes:
        """Returns a packed `hal_syspage_t` structure for a given platform"""
        raise NotImplementedError

    def post_process(self, image: BinaryIO, symbols: Optional[Dict[str, int]] = None, *, args: Iterable[str] = ()) -> None:
        """
        Performs whatever additional processing is necessary for a given platform after syspage has been written.
        It operates on the binary image directly. After exiting, the file's position will be restored.
        """
        # No post-processing necessary
        pass


class HalImx6ull(HalPart):
    HAL_SYSPAGE_SIZE = 4
    SYMBOLS = ("init_vectors", "ivt")

    def pack(self, *, image_size: int) -> bytes:
        # On this platform the first word of `hal_syspage_t` must contain the total image size
        # (see hal/armv7a/imx6ull/_init.S)
        return struct.pack("<I", image_size)

    def post_process(self, image: BinaryIO, symbols: Optional[Dict[str, int]] = None, *, args: Iterable[str] = ()) -> None:
        assert symbols is not None
        args_set = set(args)
        sdp_upload = "sdp-upload" in args_set
        if sdp_upload:
            args_set.remove("sdp-upload")

        if args_set:
            raise RuntimeError(f"Unrecognized post-processing option(s): {', '.join(args_set)}")

        pos_restore = image.tell()
        image.seek(0, os.SEEK_END)
        image_size = image.tell()

        ivt_offset = symbols["ivt"] - symbols["init_vectors"]
        if ivt_offset < 0:
            raise RuntimeError(f"IVT offset invalid ({ivt_offset})")

        image.seek(ivt_offset)
        ivt = ImxIvt.unpack(image.read(ImxIvt.SIZE))
        boot_data_offset = ivt.calculate_offset(ivt.boot_data, ivt_offset)
        image.seek(boot_data_offset)
        boot_data = ImxBootData.unpack(image.read(ImxBootData.SIZE))

        # Update size in boot data
        boot_data.load_size = image_size
        image.seek(boot_data_offset)
        image.write(boot_data.pack())

        # An image for upload through SDP needs to have the DCD pointer zeroed out (DCD is uploaded separately)
        if sdp_upload:
            ivt.dcd = 0
            image.seek(ivt_offset)
            image.write(ivt.pack())

        image.seek(pos_restore)


@dataclass(frozen=True)
class PlolessTarget:
    """Target booting the kernel image directly, with the whole syspage embedded"""
    hal: HalPart
    load_addr: int                # default physical address of the image in memory
    window: Tuple[str, str, str]  # kernel ELF symbols: image start, syspage start, syspage end

    def syspage_area(self, symbols: Dict[str, int]) -> Tuple[int, int]:
        """Syspage offset in the image and its max size, from the `window` symbols values"""
        img_start, sp_start, sp_end = (symbols[name] for name in self.window)
        return sp_start - img_start, sp_end - sp_start


PLOLESS_TARGETS: Dict[str, PlolessTarget] = {
    "armv7a7-imx6ull": PlolessTarget(HalImx6ull(), 0x80000000, ("init_vectors", "syspage_data", "syspage_end")),
}


def get_ploless_target(target: str) -> PlolessTarget:
    """Target definition from TARGET string (`family-subfamily[-project]`)"""
    name = "-".join(target.split("-")[:2])
    if name not in PLOLESS_TARGETS:
        raise ValueError(f"{target}: HAL part of the syspage can't be built on host "
                         f"(supported plo-less targets: {', '.join(PLOLESS_TARGETS)})")
    return PLOLESS_TARGETS[name]
