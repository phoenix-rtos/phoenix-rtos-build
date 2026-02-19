#!/usr/bin/env python3
#
# Script to remove references to .symtab from relocation section and then run strip
#
# Copyright 2022, 2024, 2026 Phoenix Systems
# Author: Andrzej Glowinski, Marek Bialowas
#

import shutil
import subprocess
import sys
import tempfile
from io import BytesIO
from dataclasses import dataclass
from enum import IntFlag, IntEnum
import struct
from typing import ClassVar, Type, List, Tuple

import shutil

EI_NIDENT = 16

class EiClass(IntEnum):
    """EI_CLASS field from e_ident that determines if elf is 32 or 64-bit"""
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2


class EiData(IntEnum):
    """EI_DATA field from e_ident that determines if elf is little or big endian"""
    ELFDATANONE = 0
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

    def to_format(self):
        return {EiData.ELFDATA2LSB: "<", EiData.ELFDATA2MSB: ">"}[self]


# Types only needed for resolving relocations
class ShType(IntEnum):
    """Interpretation of sh_type field of ElfXX_Shdr struct. Determines section type"""
    SHT_NULL = 0
    SHT_PROGBITS =  1
    SHT_SYMTAB =  2
    SHT_STRTAB =  3
    SHT_RELA =  4
    SHT_HASH =  5
    SHT_DYNAMIC =  6
    SHT_NOTE =  7
    SHT_NOBITS =  8
    SHT_REL =  9
    SHT_SHLIB =  10
    SHT_DYNSYM =  11
    SHT_LOPROC =  0x70000000
    SHT_HIPROC =  0x7fffffff
    SHT_LOUSER =  0x80000000
    SHT_HIUSER = 0xffffffff


class PhType(IntEnum):
    PT_NULL = 0            # Unused segment.
    PT_LOAD = 1            # Loadable segment.
    PT_DYNAMIC = 2         # Dynamic linking information.
    PT_INTERP = 3          # Interpreter pathname.
    PT_NOTE = 4            # Auxiliary information.
    PT_SHLIB = 5           # Reserved.
    PT_PHDR = 6            # The program header table itself.
    PT_TLS = 7             # The thread-local storage template.
    PT_LOOS = 0x60000000   # Lowest operating system-specific pt entry type.
    PT_HIOS = 0x6fffffff   # Highest operating system-specific pt entry type.
    PT_LOPROC = 0x70000000 # Lowest processor-specific program hdr entry type.
    PT_HIPROC = 0x7fffffff # Highest processor-specific program hdr entry type.

    # x86-64 program header types.
    # These all contain stack unwind tables.
    PT_GNU_EH_FRAME = 0x6474e50
    PT_SUNW_EH_FRAME = 0x6474e50
    PT_SUNW_UNWIND = 0x6464e50

    PT_GNU_STACK = 0x6474e551    # Indicates stack executability.
    PT_GNU_RELRO = 0x6474e552    # Read-only after relocation.
    PT_GNU_PROPERTY = 0x6474e553 # .note.gnu.property notes sections.

    PT_OPENBSD_MUTABLE = 0x65a3dbe5   # Like bss, but not immutable.
    PT_OPENBSD_RANDOMIZE = 0x65a3dbe6 # Fill with random data.
    PT_OPENBSD_WXNEEDED = 0x65a3dbe7  # Program does W^X violations.
    PT_OPENBSD_NOBTCFI = 0x65a3dbe8   # Do not enforce branch target CFI.
    PT_OPENBSD_SYSCALLS = 0x65a3dbe9  # System call sites.
    PT_OPENBSD_BOOTDATA = 0x65a41be6  # Section for boot arguments.

    # ARM program header types.
    PT_ARM_ARCHEXT = 0x70000000 # Platform architecture compatibility info
    # These all contain stack unwind tables.
    PT_ARM_EXIDX = 0x70000001
    PT_ARM_UNWIND = 0x70000001
    # MTE memory tag segment type
    PT_AARCH64_MEMTAG_MTE = 0x70000002

    # MIPS program header types.
    PT_MIPS_REGINFO = 0x70000000  # Register usage information.
    PT_MIPS_RTPROC = 0x70000001   # Runtime procedure table.
    PT_MIPS_OPTIONS = 0x70000002  # Options segment.
    PT_MIPS_ABIFLAGS = 0x70000003 # Abiflags segment.

    # RISCV program header types.
    PT_RISCV_ATTRIBUTES = 0x70000003


# Segment flag bits.
class PhFlags(IntFlag):
    PF_X = 1                # Execute
    PF_W = 2                # Write
    PF_R = 4                # Read
    PF_MASKOS = 0x0ff00000  # Bits for operating system-specific semantics.
    PF_MASKPROC = 0xf0000000 # Bits for processor-specific semantics.


class ElfStruct:
    """Abstract for every ELF struct"""
    FORMAT: ClassVar[List[Tuple[str, str]]]

    @classmethod
    def parse(cls, b: bytes, e: EiData):
        data = struct.unpack(e.to_format() + cls._get_format(), b)
        return cls(**dict(zip(cls._get_params(), data)))

    def serialize(self, e: EiData):
        return struct.pack(e.to_format() + self._get_format(), *(getattr(self, name) for name in self._get_params()))

    @property
    def size(self):
        return self.get_size()

    @classmethod
    def get_size(cls):
        return struct.calcsize(f"={cls._get_format()}")

    @classmethod
    def _get_format(cls):
        return ''.join(tuple(zip(*cls.FORMAT))[0])

    @classmethod
    def _get_params(cls):
        return tuple(zip(*cls.FORMAT))[1]


@dataclass
class ElfEident:
    """ElfXX_Ehdr e_ident field"""
    e_ident: bytes

    def get_class(self):
        return EiClass(self.e_ident[4])

    def get_endianness(self):
        return EiData(self.e_ident[5])

    @classmethod
    def parse(cls, b: bytes) -> "ElfEident":
        return cls(*struct.unpack("16s", b))

    def __post_init__(self):
        if self.e_ident[0:4] != b"\x7fELF":
            raise ValueError(f"ELF magic invalid: {self.e_ident[0:4]}")
        if self.get_class() != EiClass.ELFCLASS32:
            raise NotImplementedError("Only 32 bit ELF files is supported")


@dataclass
class ElfEhdr(ElfStruct):
    """Abstraction for structs Elf32_Ehdr and Elf64_Ehdr"""
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass
class Elf32Ehdr(ElfEhdr):
    """struct Elf32_Ehdr without e_ident field"""
    FORMAT = [
        ("H", "e_type"),
        ("H", "e_machine"),
        ("I", "e_version"),
        ("I", "e_entry"),
        ("I", "e_phoff"),
        ("I", "e_shoff"),
        ("I", "e_flags"),
        ("H", "e_ehsize"),
        ("H", "e_phentsize"),
        ("H", "e_phnum"),
        ("H", "e_shentsize"),
        ("H", "e_shnum"),
        ("H", "e_shstrndx")
    ]


@dataclass
class ElfShdr(ElfStruct):
    """Abstraction for structs Elf32_Shdr and Elf64_Shdr"""
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    
    def content(self, b: BytesIO) -> bytes:
        old_offset = b.tell()
        b.seek(self.sh_offset)
        res: bytes = b.read(self.sh_size)
        b.seek(old_offset)
        return res
    
    @staticmethod
    def from_eclass(ecls: EiClass) -> Type["ElfShdr"]:
        return {EiClass.ELFCLASS32: Elf32Shdr}[ecls]


@dataclass
class Elf32Shdr(ElfShdr):
    """struct Elf32_Shdr"""
    FORMAT = [
        ("I", "sh_name"),
        ("I", "sh_type"),
        ("I", "sh_flags"),
        ("I", "sh_addr"),
        ("I", "sh_offset"),
        ("I", "sh_size"),
        ("I", "sh_link"),
        ("I", "sh_info"),
        ("I", "sh_addralign"),
        ("I", "sh_entsize")
    ]


@dataclass
class ElfPhdr(ElfStruct):
    """"Abstraction for structs Elf32_Phdr and Elf64_Phdr"""
    p_type: PhType
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: PhFlags
    p_align: int

    def __post_init__(self):
        self.p_type = PhType(self.p_type)
        self.p_flags = PhFlags(self.p_flags)
    
    def content(self, b: BytesIO) -> bytes:
        old_offset = b.tell()
        b.seek(self.p_offset)
        res: bytes = b.read(self.p_filesz)
        b.seek(old_offset)
        return res


@dataclass
class Elf32Phdr(ElfPhdr):
    """"Struct Elf32_Phdr"""
    FORMAT = [
        ("I", "p_type"),
        ("I", "p_offset"),
        ("I", "p_vaddr"),
        ("I", "p_paddr"),
        ("I", "p_filesz"),
        ("I", "p_memsz"),
        ("I", "p_flags"),
        ("I", "p_align")
    ]


@dataclass
class ElfRelx(ElfStruct):
    """Abstraction for structs Elf32_Rel, Elf64_Rel, Elf32_Rela, Elf64_Rela"""
    r_offset: int
    r_info: int


@dataclass
class Elf32Rel(ElfRelx):
    """struct Elf32_Rel"""
    FORMAT = [
        ("I", "r_offset"),
        ("I", "r_info")
    ]


class ElfFixedSizeTable:
    offset: int
    size: int
    entrySize: int
    header: Type[ElfStruct]
    parser: "ElfParser"

    def __init__(self, p: "ElfParser"):
        self.parser = p

    def __iter__(self):
        for off in range(self.offset, self.offset + self.size, self.entrySize):
            assert self.entrySize == self.header.get_size()
            yield self.parser.read_struct(self.header, off), off
    
    def __getitem__(self, index: int):
        assert self.entrySize == self.header.get_size()
        ent_off: int = index * self.entrySize
        if ent_off >= self.size:
            raise IndexError("Table index out of bounds")
        return self.parser.read_struct(self.header, self.offset + ent_off), self.offset + ent_off

    def __str__(self) -> str:
        return "\n".join([str(s) for s, _ in self])


class ElfSectionTable(ElfFixedSizeTable):
    header: Type[ElfShdr]

    def __init__(self, e: ElfEhdr, p: "ElfParser"):
        super().__init__(p)
        self.header = {EiClass.ELFCLASS32: Elf32Shdr}[p.ident.get_class()]
        self.offset = e.e_shoff
        self.size = e.e_shnum * e.e_shentsize
        self.entrySize = e.e_shentsize


class ElfPhdrTable(ElfFixedSizeTable):
    header: Type[ElfPhdr]

    def __init__(self, e: ElfEhdr, p: "ElfParser"):
        super().__init__(p)
        self.header = {EiClass.ELFCLASS32: Elf32Phdr}[p.ident.get_class()]
        self.offset = e.e_phoff
        self.size = e.e_phnum * e.e_phentsize
        self.entrySize = e.e_phentsize


class ElfRelocationTable(ElfFixedSizeTable):
    header: Type[ElfRelx]

    def __init__(self, s: ElfShdr, p: "ElfParser"):
        super().__init__(p)
        self.header = {(EiClass.ELFCLASS32, ShType.SHT_REL): Elf32Rel}[p.ident.get_class(), ShType(s.sh_type)]
        self.offset = s.sh_offset
        self.size = s.sh_size
        self.entrySize = s.sh_entsize


class ElfParser:
    data: BytesIO
    ident: ElfEident
    header: ElfEhdr

    def __init__(self, b: BytesIO):
        self.data = b
        self.ident = ElfEident.parse(self.data.read(EI_NIDENT))
        header_type = {EiClass.ELFCLASS32: Elf32Ehdr}[self.ident.get_class()]
        header = self.read_struct(header_type, EI_NIDENT)
        assert isinstance(header, ElfEhdr)
        self.header = header

    def read_struct(self, st: Type[ElfStruct], offset):
        self.data.seek(offset)
        data = self.data.read(st.get_size())
        return st.parse(data, self.ident.get_endianness())

    def write_struct(self, st: ElfStruct, offset):
        self.data.seek(offset)
        self.data.write(st.serialize(self.ident.get_endianness()))

    def get_sections(self) -> ElfSectionTable:
        return ElfSectionTable(self.header, self)

    def get_relocations(self, s: ElfShdr) -> ElfRelocationTable:
        return ElfRelocationTable(s, self)

    def get_program_headers(self) -> ElfPhdrTable:
        return ElfPhdrTable(self.header, self)
    
    def get_ehdr_bytes(self) -> bytes:
        self.data.seek(0)
        ident_bytes = self.data.read(EI_NIDENT)
        return ident_bytes + self.header.serialize(self.ident.get_endianness())
    
    def _update_header_offsets(self, expaned_at: int, offset_by: int):
        """Update header offsets after payload was expanded at a given address"""
        for ph, ph_off in self.get_program_headers():
            if ph.p_offset <= expaned_at:
                continue
            ph.p_offset += offset_by
            self.write_struct(ph, ph_off)
        
        for sh, sh_off in self.get_sections():
            if sh.sh_offset <= expaned_at or sh.sh_type == ShType.SHT_NOBITS:
                continue
            sh.sh_offset += offset_by
            self.write_struct(sh, sh_off)

    def add_section(self, name: str, content: bytes):
        if not self.data.writable():
            raise ValueError("Writing not supported for this object")
        if not self.data.seekable():
            raise ValueError("Seeking not supported for this object")
        
        # Add new name to strtab
        shtab: ElfSectionTable = self.get_sections()
        strtab_hdr: ElfShdr
        strtab_hdr, _ = shtab[self.header.e_shstrndx]

        self.data.seek(strtab_hdr.sh_offset)
        strtab = bytearray(self.data.read(strtab_hdr.sh_size))
        strtab.extend(name.encode(encoding="ascii") + b"\0")

        rest = self.data.read()

        self.data.seek(strtab_hdr.sh_offset)
        self.data.write(strtab)
        self.data.write(rest)
        self.data.seek(0)

        added_bytes: int = len(name) + 1

        self.header.e_shoff += added_bytes
        self.write_struct(self.header, EI_NIDENT)

        shtab = self.get_sections()
        strtab_hdr, strtab_hdr_off = shtab[self.header.e_shstrndx]
        strtab_index: int = strtab_hdr.sh_size
        strtab_hdr.sh_size += len(name) + 1
        self.write_struct(strtab_hdr, strtab_hdr_off)

        # Sections/segments that come after the extended names section must have their offsets moved
        self._update_header_offsets(strtab_hdr.sh_offset, added_bytes)

        # Add new section content after the last section
        shtab = self.get_sections()
        last_sh, _ = shtab[self.header.e_shnum - 1]
        expand_at: int = last_sh.sh_offset + last_sh.sh_size
        self.data.seek(expand_at)
        rest = self.data.read()
        self.data.seek(expand_at)
        self.data.write(content)
        self.data.write(rest)

        self.header.e_shoff += len(content)
        self.write_struct(self.header, EI_NIDENT)
        self._update_header_offsets(expand_at, len(content))
        new_sh_off: int = expand_at

        # Add a new section header
        shtab = self.get_sections()

        last_sh, last_sh_off = shtab[self.header.e_shnum - 1]
        expand_at: int = last_sh_off + self.header.e_shentsize
        self.data.seek(expand_at)
        rest = self.data.read()

        sh_class = ElfShdr.from_eclass(self.ident.get_class())
        assert sh_class.get_size() == self.header.e_shentsize
        
        section_hdr = sh_class(strtab_index, ShType.SHT_NOTE, 0, 0, new_sh_off, len(content), 0, 0, 0, 0)
        self.write_struct(section_hdr, expand_at)
        self.header.e_shnum += 1
        self.write_struct(self.header, EI_NIDENT)
    
    def set_section_content(self, name: str, content: bytes):
        shtab: ElfSectionTable = self.get_sections()
        strtab_hdr: ElfShdr
        strtab_hdr, _ = shtab[self.header.e_shstrndx]
        strtab = strtab_hdr.content(self.data)

        bname = name.encode(encoding="ascii")

        for sh, _ in shtab:
            if strtab[sh.sh_name:strtab.find(b"\0", sh.sh_name + 1)] != bname:
                continue
            if sh.sh_size != len(content):
                raise ValueError("New content length must be the same")
            self.data.seek(sh.sh_offset)
            self.data.write(content)
            return
        
        raise KeyError(f"Section with name: {name} not found")


def remove_symtab_references(in_file, out_file):
    with open(in_file, "rb") as file:
        shutil.copyfileobj(file, out_file)
    out_file.seek(0)

    elf = ElfParser(out_file)
    for s, _ in elf.get_sections():
        # Get sections connected with relocations
        if s.sh_type in (ShType.SHT_REL, ShType.SHT_RELA):
            # Iterate over relocations
            for r, r_off in elf.get_relocations(s):
                # r_info field of Rel(a) struct contain both relocation type (on LSB) and symbol table index on rest.
                # Preserve relocation type but set symbol table index to 0 (STN_UNDEF) for each relocation
                r.r_info &= 0xff
                elf.write_struct(r, r_off)


def validate_args():
    return not sys.argv[1].startswith("-") and "-o" in sys.argv[2:-2]


def strip_wrapper():
    # Many input files without -o on strip call is not supported by this wrapper
    if not validate_args():
        print(f"Usage: {sys.argv[0]} strip_binary <strip options> -o out_file in_file", file=sys.stderr)
        sys.exit(1)

    in_file = sys.argv[-1]
    with tempfile.NamedTemporaryFile() as tmp_file:
        remove_symtab_references(in_file, tmp_file)
        tmp_file.flush()
        subprocess.check_call([*sys.argv[1:-1], tmp_file.name])


if __name__ == '__main__':
    strip_wrapper()
