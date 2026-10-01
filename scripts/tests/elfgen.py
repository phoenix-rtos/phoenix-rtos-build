#
# Minimal ELF32 (little-endian) file generator for image_builder/strip tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Union

PT_LOAD = 1
PT_ARM_EXIDX = 0x70000001
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551

PF_X = 1
PF_W = 2
PF_R = 4

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_REL = 9

EHDR_SIZE = 52
PHDR_SIZE = 32
SHDR_SIZE = 40


@dataclass
class Segment:
    type: int
    flags: int
    vaddr: int = 0
    filesz: int = 0
    memsz: int = 0
    align: int = 0x1000


@dataclass
class Section:
    name: str
    type: int
    data: bytes = b""
    link: Union[int, str] = 0  # section index or name
    entsize: int = 0


# program headers of a real armv7a7-imx6ull kernel (text + rodata, bss only)
KERNEL_SEGMENTS = (
    Segment(PT_ARM_EXIDX, PF_R, 0xc0016e10, 0x8, 0x8, 0x4),
    Segment(PT_LOAD, PF_R | PF_X, 0xc0000000, 0x16e18, 0x16e18),
    Segment(PT_LOAD, PF_R | PF_W, 0xc0018000, 0x0, 0x186ec, 0x4000),
    Segment(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0x10),
)


def rel_section(name: str, relocs: Iterable[tuple[int, int]]) -> Section:
    """SHT_REL section from (r_offset, r_info) pairs"""
    return Section(name, SHT_REL, b"".join(struct.pack("<II", *r) for r in relocs), entsize=8)


def symtab_sections(symbols: Dict[str, int]) -> List[Section]:
    """.symtab + .strtab with local NOTYPE symbols (like the kernel's asm labels)"""
    strtab = b"\0"
    symtab = bytes(16)  # STN_UNDEF
    for name, value in symbols.items():
        symtab += struct.pack("<IIIBBH", len(strtab), value, 0, 0, 0, 1)
        strtab += name.encode() + b"\0"
    return [Section(".symtab", SHT_SYMTAB, symtab, link=".strtab", entsize=16), Section(".strtab", SHT_STRTAB, strtab)]


def make_elf32(path: Path, segments: Iterable[Segment] = (), sections: Iterable[Section] = (),
               ident: bytes = b"\x7fELF\x01\x01\x01") -> Path:
    """Write ELF32 file with the given program headers (no segment data) and sections"""
    segments = list(segments)
    sections = [Section("", 0)] + list(sections)

    shstrtab = b"\0"
    name_offs = []
    for s in sections[1:]:
        name_offs.append(len(shstrtab))
        shstrtab += s.name.encode() + b"\0"
    name_offs.append(len(shstrtab))
    shstrtab += b".shstrtab\0"
    sections.append(Section(".shstrtab", SHT_STRTAB, shstrtab))
    names = [0] + name_offs

    phoff = EHDR_SIZE
    data_offs = phoff + PHDR_SIZE * len(segments)
    body = b""
    offsets = []
    for s in sections:
        offsets.append(data_offs + len(body))
        body += s.data
    shoff = data_offs + len(body)

    index = {s.name: i for i, s in enumerate(sections)}
    ehdr = ident.ljust(16, b"\0") + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0, phoff if segments else 0, shoff, 0,
        EHDR_SIZE, PHDR_SIZE, len(segments), SHDR_SIZE, len(sections), len(sections) - 1)
    phdrs = b"".join(struct.pack("<IIIIIIII", p.type, 0, p.vaddr, p.vaddr, p.filesz, p.memsz, p.flags, p.align)
                     for p in segments)
    shdrs = b""
    for i, s in enumerate(sections):
        link = index[s.link] if isinstance(s.link, str) else s.link
        size = len(s.data) if i else 0
        shdrs += struct.pack("<IIIIIIIIII", names[i], s.type, 0, 0, offsets[i] if i else 0, size, link, 0, 1, s.entsize)

    path.write_bytes(ehdr + phdrs + body + shdrs)
    return path
