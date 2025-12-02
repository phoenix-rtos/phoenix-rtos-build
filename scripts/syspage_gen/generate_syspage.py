#!/usr/bin/env python3

# Phoenix-RTOS
#
# Script to generate syspage
#
# Copyright 2025 Phoenix Systems
# Author: Damian Jozwiak
#
# %LICENSE%


import argparse
import logging
import struct
import subprocess
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from pathlib import Path
from string import hexdigits

from hal_armv7m_stm32_l4 import SyspageHalStruct, LINKER_SYMBOLS, hal_get_memory_areas

ADDR_T = "I"
SIZE_T = "I"
PTR_T = "I"
ENUM_T = "B"
UINT_T = "I"
UCHAR_T = "B"
PADDING_T = "B"

ALIGN_DEFAULT = 8
ALIGN_CHAR = b"\x00"
MAGIC = b"dabaabad"


def add_padding_align(data: bytes, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
    assert align >= 0, "The align must be greater than zero."
    end = addr + len(data)
    end_align = (end + align - 1) & ~(align - 1)
    return data + ((end_align - end) * align_char)


def calc_size_with_align(data_len: int, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
    assert align >= 0, "The align must be greater than zero."
    end = addr + data_len
    end_align = (end + align - 1) & ~(align - 1)
    return data_len + (end_align - end)


def pack_align_magic(
    magic: bytes = MAGIC, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR
) -> bytes:
    magic_data = struct.pack("8s", magic)
    return add_padding_align(magic_data, addr, align, align_char)


@dataclass
class SyspageChar:
    data: bytes = b""

    def pack_align(self, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
        if not self.data:
            return b""
        return add_padding_align(self.data, addr, align, align_char)

    def pack_align_size(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
        if not self.data:
            return 0
        return calc_size_with_align(len(self.data), addr, align)


@dataclass
class SyspageMapEntStruct:
    class EntryType(IntEnum):
        RESERVED = 0
        TEMP = 1
        ALLOCATED = 2
        INVALID = 3

    _FMT = "<" + PTR_T * 2 + ENUM_T + ADDR_T * 2
    next_ptr: int = 0
    prev_ptr: int = 0
    ent_type: int = EntryType.RESERVED
    start_addr: int = 0
    end_addr: int = 0

    def pack_align(self, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
        data = struct.pack(self._FMT, self.next_ptr, self.prev_ptr, self.ent_type, self.start_addr, self.end_addr)
        return add_padding_align(data, addr, align, align_char)

    def pack_align_size(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
        return calc_size_with_align(self.core_size(), addr, align)

    @classmethod
    def core_size(cls) -> int:
        return struct.calcsize(cls._FMT)


class SyspageMapAttr(IntFlag):
    READ = 0x01
    WRITE = 0x02
    EXEC = 0x04
    SHAREABLE = 0x08
    CACHEABLE = 0x10
    BUFFERABLE = 0x20

    @classmethod
    def from_cmd_str(cls, value: str):
        map_attr = {
            "r": cls.READ,
            "w": cls.WRITE,
            "x": cls.EXEC,
            "s": cls.SHAREABLE,
            "c": cls.CACHEABLE,
            "b": cls.BUFFERABLE,
        }
        return sum(map_attr[x] for x in value)


@dataclass
class SyspageMapStruct:
    _FMT = "<" + PTR_T * 2 + PTR_T + ADDR_T * 2 + UINT_T + UCHAR_T + PTR_T
    next_ptr: int = 0
    prev_ptr: int = 0
    _entries_ptr: int = 0  # mapent_t*
    _entries: list[SyspageMapEntStruct] = field(default_factory=list)
    start_addr: int = 0
    end_addr: int = 0
    attr: SyspageMapAttr = SyspageMapAttr.READ
    map_id: int = 0
    _name_ptr: int = 0  # char*
    name: SyspageChar = field(default_factory=SyspageChar)

    def add_entries_based_on_ld_symbols(
        self, hal_memory_map_entries: list[tuple[int, int, int]], syspage_start_addr: int
    ) -> bool:
        entry_for_syspage_allocated = False

        # If syspage is located in the heap, this area should be RESERVED not TEMP (area from start syspage to __heap_limit)
        # PLO sets syspage at the beginning of the heap
        entries = self._get_entries(self.start_addr, self.end_addr, hal_memory_map_entries)
        for e in entries:
            if e[0] <= syspage_start_addr < e[1]:
                # if syspage is located in the heap make entry RESERVED
                self.add_entry(e[0], e[1], SyspageMapEntStruct.EntryType.RESERVED)
                entry_for_syspage_allocated = True
            else:
                self.add_entry(*e)
        return entry_for_syspage_allocated

    def pack_align(self, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
        """(syspage_map_t + align) + (name + align) + (mapent_t + align) + (mapent_t + align) + ..."""
        self._calc_ptr(addr, align)
        data = add_padding_align(self._pack_core(), addr, align, align_char)
        data += self.name.pack_align(addr + len(data), align, align_char)
        for ent in self._entries:
            data += ent.pack_align(addr + len(data), align, align_char)
        return data

    def pack_align_size(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
        size = calc_size_with_align(self.core_size(), addr, align)
        size += self.name.pack_align_size(addr + size, align)
        for ent in self._entries:
            size += ent.pack_align_size(addr + size, align)
        return size

    def is_in_map(self, start: int, end: int) -> bool:
        return self.start_addr <= start and self.end_addr >= end

    def are_entries_overlapping(self, start: int, end: int) -> bool:
        for e in self._entries:
            if max(e.start_addr, start) < min(e.end_addr, end):
                return True
        return False

    def add_entry(
        self,
        start_addr: int = 0,
        end_addr: int = 0,
        entry_type: SyspageMapEntStruct.EntryType = SyspageMapEntStruct.EntryType.RESERVED,
    ) -> None:
        if start_addr == 0 and end_addr == 0:
            raise ValueError("Invalid map entry (missing start/end addresses)")

        if not self.is_in_map(start_addr, end_addr):
            raise ValueError("Invalid map entry (beyond the definition of a map)")

        if self.are_entries_overlapping(start_addr, end_addr):
            raise ValueError("Invalid map entry (overlapping)")

        if start_addr > end_addr:
            raise ValueError("Invalid map entry (wrong start/end addresses)")

        self._entries.append(SyspageMapEntStruct(ent_type=entry_type, start_addr=start_addr, end_addr=end_addr))
        self._entries.sort(key=lambda e: e.start_addr)

    def _get_next_entry(
        self, search_start: int, search_end: int, entries: list[tuple[int, int, int]]
    ) -> tuple[int, int, int] | None:
        """
        Finds one entry, the closest one (with the lowest start address),
        that overlaps the searched range [search_start, search_end).
        """
        min_entry: tuple[int, int, int] | None = None

        for entry_start, entry_end, entry_type in entries:
            if entry_start >= entry_end:
                continue

            common_start = max(search_start, entry_start)
            common_end = min(search_end, entry_end)

            if common_start < common_end:
                current_entry = (common_start, common_end, entry_type)
                if min_entry is None:
                    min_entry = current_entry
                if current_entry[0] < min_entry[0]:
                    min_entry = current_entry
        return min_entry

    def _get_entries(
        self, map_start: int, map_end: int, entries: list[tuple[int, int, int]]
    ) -> list[tuple[int, int, int]]:

        entries_ordered_list = []
        current_pos = map_start

        while current_pos < map_end:
            next_entry = self._get_next_entry(current_pos, map_end, entries)
            if next_entry is None:
                break
            assert next_entry[1] > current_pos, "Invalid next entry detected"
            entries_ordered_list.append(next_entry)
            current_pos = next_entry[1]

        return entries_ordered_list

    def _link_circular_list(self, items: list[SyspageMapEntStruct], start_addr: int, align: int) -> tuple[int, int]:
        if not items:
            return 0, start_addr
        item_addrs = []
        current_addr = start_addr
        for item in items:
            item_addrs.append(current_addr)
            current_addr += item.pack_align_size(current_addr, align)

        next_available_addr = current_addr

        for i, item in enumerate(items):
            item.prev_ptr = item_addrs[i - 1]
            item.next_ptr = item_addrs[(i + 1) % len(items)]

        return item_addrs[0], next_available_addr

    def _calc_ptr(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> None:
        next_available_addr = addr + calc_size_with_align(self.core_size(), addr, align)

        size = self.name.pack_align_size(addr, align)
        self._name_ptr = next_available_addr if size else 0
        next_available_addr += size

        (self._entries_ptr, _) = self._link_circular_list(self._entries, next_available_addr, align)

    def _pack_core(self) -> bytes:
        return struct.pack(
            self._FMT,
            self.next_ptr,
            self.prev_ptr,
            self._entries_ptr,
            self.start_addr,
            self.end_addr,
            self.attr,
            self.map_id,
            self._name_ptr,
        )

    @classmethod
    def core_size(cls) -> int:
        return struct.calcsize(cls._FMT)


@dataclass
class SyspageProgStruct:
    _FMT = "<" + PTR_T * 2 + ADDR_T * 2 + PTR_T + SIZE_T + PTR_T + SIZE_T + PTR_T
    next_ptr: int = 0
    prev_ptr: int = 0
    start_addr: int = 0
    end_addr: int = 0
    _argv_ptr: int = 0  # char*
    argv: SyspageChar = field(default_factory=SyspageChar)
    imap_sz: int = 0
    _imaps_ptr: int = 0  # char*
    imaps: SyspageChar = field(default_factory=SyspageChar)
    dmap_sz: int = 0
    _dmaps_ptr: int = 0  # char*
    dmaps: SyspageChar = field(default_factory=SyspageChar)

    def pack_align(self, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
        """(syspage_map_t + align) + (char argv[] + align) + (char imaps[] + align) + (char dmaps[] + align)"""
        self._calc_ptr(addr, align)
        data = add_padding_align(self._pack_core(), addr, align, align_char)
        data += self.argv.pack_align(addr + len(data), align, align_char)
        data += self.imaps.pack_align(addr + len(data), align, align_char)
        data += self.dmaps.pack_align(addr + len(data), align, align_char)
        return data

    def pack_align_size(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
        size = calc_size_with_align(self.core_size(), addr, align)
        size += self.argv.pack_align_size(addr + size, align)
        size += self.imaps.pack_align_size(addr + size, align)
        size += self.dmaps.pack_align_size(addr + size, align)
        return size

    def _calc_ptr(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> None:
        next_available_addr = addr + calc_size_with_align(self.core_size(), addr, align)

        size = self.argv.pack_align_size()
        self._argv_ptr = next_available_addr if size else 0
        next_available_addr += size

        size = self.imaps.pack_align_size()
        self._imaps_ptr = next_available_addr if size else 0
        next_available_addr += size

        size = self.dmaps.pack_align_size()
        self._dmaps_ptr = next_available_addr if size else 0
        next_available_addr += size

    def _pack_core(self) -> bytes:
        return struct.pack(
            self._FMT,
            self.next_ptr,
            self.prev_ptr,
            self.start_addr,
            self.end_addr,
            self._argv_ptr,
            self.imap_sz,
            self._imaps_ptr,
            self.dmap_sz,
            self._dmaps_ptr,
        )

    @classmethod
    def core_size(cls) -> int:
        return struct.calcsize(cls._FMT)


# TODO: Provide a mechanism for array align (table[16] __attribute__((aligned(8)));)
@dataclass
class SyspageStruct:
    _FMT = "<" + SIZE_T + ADDR_T + PTR_T + PTR_T + UINT_T  # without hal part of the syspage structure
    hal_syspage: SyspageHalStruct = field(default_factory=SyspageHalStruct)
    _size_syspage: int = 0  # real size of syspage (structure field)
    pkernel: int = 0
    _maps_ptr: int = 0  # syspage_map_t*
    _maps: list[SyspageMapStruct] = field(default_factory=list)
    _progs_ptr: int = 0  # syspage_prog_t*
    _progs: list[SyspageProgStruct] = field(default_factory=list)
    console: int = 0

    _syspage_start_addr: int = 0
    _syspage_end_addr: int = 0
    _entry_for_syspage_allocated: bool = False
    _hal_memory_map_entries: list[tuple[int, int, int]] | None = None

    def fill_in_hal_part(self):
        self.hal_syspage.invalidate()
        for m in self._maps:
            self.hal_syspage.alloc_mpu_region(m.start_addr, m.end_addr, m.attr, m.map_id, 1)

    def add_map(
        self,
        start_addr: int = 0,
        end_addr: int = 0,
        attr: int = 0,
        name: bytes = b"",
    ) -> None:

        self._validate_new_map(name, start_addr, end_addr)

        # map_id: maps are numbered in the order they are added
        map_struct = SyspageMapStruct(
            start_addr=start_addr,
            end_addr=end_addr,
            attr=attr,
            name=SyspageChar(data=name),
            map_id=len(self._maps),
        )

        if self._hal_memory_map_entries is not None:
            self._entry_for_syspage_allocated = map_struct.add_entries_based_on_ld_symbols(
                self._hal_memory_map_entries, self._syspage_start_addr
            )

        # When syspage is in the “map” area and has not yet been allocated
        if (not self._entry_for_syspage_allocated) and (start_addr <= self._syspage_start_addr < end_addr):
            map_struct.add_entry(
                self._syspage_start_addr,
                self._syspage_end_addr,
                SyspageMapEntStruct.EntryType.RESERVED,
            )

        self._maps.append(map_struct)

    def add_entry_into_map(
        self,
        start_addr: int = 0,
        end_addr: int = 0,
        entry_type: SyspageMapEntStruct.EntryType = SyspageMapEntStruct.EntryType.ALLOCATED,
    ):
        for m in self._maps:
            if m.is_in_map(start_addr, end_addr):
                m.add_entry(start_addr, end_addr, entry_type)
                return
        raise ValueError("No map defined for the requested entry range")

    def add_prog(
        self,
        map_name: bytes = b"",
        offs: int = 0,
        size: int = 0,
        flag_exec: bool = False,
        argv: bytes = b"",
        imaps: list[bytes] | None = None,
        dmaps: list[bytes] | None = None,
    ) -> None:
        current_map = self._get_map_by_name(map_name)
        if current_map is None:
            raise ValueError("No map defined for requested app")

        app_start_addr = current_map.start_addr + offs
        app_end_addr = app_start_addr + size

        current_map.add_entry(
            start_addr=app_start_addr,
            end_addr=app_end_addr,
            entry_type=SyspageMapEntStruct.EntryType.ALLOCATED,
        )

        if flag_exec:
            argv = b"X" + argv

        imaps_id = b""
        dmaps_id = b""
        if imaps is None:
            imaps = []
        if dmaps is None:
            dmaps = []

        for i in imaps:
            map_id = self._get_map_id_by_name(i)
            if map_id is None:
                raise ValueError(f"Undefined map for {i.decode()} referenced in imaps")
            imaps_id += bytes([map_id])

        for d in dmaps:
            map_id = self._get_map_id_by_name(d)
            if map_id is None:
                raise ValueError(f"Undefined map for {d.decode()} referenced in dmaps")
            dmaps_id += bytes([map_id])

        prog_struct = SyspageProgStruct(
            start_addr=app_start_addr,
            end_addr=app_end_addr,
            argv=SyspageChar(data=argv),
            imap_sz=len(imaps_id),
            imaps=SyspageChar(data=imaps_id),
            dmap_sz=len(dmaps_id),
            dmaps=SyspageChar(data=dmaps_id),
        )

        self._progs.append(prog_struct)

    def pack_align(self, addr: int = 0, align: int = ALIGN_DEFAULT, align_char: bytes = ALIGN_CHAR) -> bytes:
        """[(hal_syspage_t + size_t + addr_t + syspage_map_t* + syspage_prog_t* + console) + align] + {_maps} + {_progs}"""
        self._calc_ptr(addr, align)
        self._size_syspage = self.pack_align_size(addr, align)
        data = add_padding_align(self._pack_core(), addr, align, align_char)
        for m in self._maps:
            data += m.pack_align(addr + len(data), align, align_char)
        for p in self._progs:
            data += p.pack_align(addr + len(data), align, align_char)
        return data

    def pack_align_size(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> int:
        size = calc_size_with_align(self.core_size(), addr, align)
        for m in self._maps:
            size += m.pack_align_size(addr + size, align)
        for p in self._progs:
            size += p.pack_align_size(addr + size, align)
        return size

    def _validate_new_map(self, name: bytes, start_addr: int, end_addr: int) -> None:
        if not name:
            raise ValueError("Invalid argument for map (empty name)")
        for m in self._maps:
            if name == m.name.data:
                raise ValueError(f"Invalid argument for map ('{name}' already exists)")
            if start_addr < m.end_addr and end_addr > m.start_addr:
                raise ValueError(f"Invalid argument for map (overlaps with '{m.name.data}')")
        if start_addr >= end_addr:
            raise ValueError("Invalid argument for map (start must be smaller than end)")

    def _get_map_by_name(self, name: bytes) -> SyspageMapStruct | None:
        for m in self._maps:
            if m.name.data == name:
                return m
        return None

    def _get_map_id_by_name(self, name: bytes) -> int | None:
        m = self._get_map_by_name(name)
        if m:
            return m.map_id
        return None

    def _link_circular_list(
        self, items: list[SyspageMapStruct | SyspageProgStruct], start_addr: int, align: int
    ) -> tuple[int, int]:
        if not items:
            return 0, start_addr
        item_addrs = []
        current_addr = start_addr
        for item in items:
            item_addrs.append(current_addr)
            current_addr += item.pack_align_size(current_addr, align)

        next_available_addr = current_addr

        for i, item in enumerate(items):
            item.prev_ptr = item_addrs[i - 1]
            item.next_ptr = item_addrs[(i + 1) % len(items)]

        return item_addrs[0], next_available_addr

    def _calc_ptr(self, addr: int = 0, align: int = ALIGN_DEFAULT) -> None:
        next_available_addr = addr + calc_size_with_align(self.core_size(), addr, align)
        self._maps_ptr, next_available_addr = self._link_circular_list(self._maps, next_available_addr, align)
        self._progs_ptr, next_available_addr = self._link_circular_list(self._progs, next_available_addr, align)

    def _pack_core(self) -> bytes:
        hs_bytes = self.hal_syspage.pack()
        return hs_bytes + struct.pack(
            self._FMT,
            self._size_syspage,
            self.pkernel,
            self._maps_ptr,
            self._progs_ptr,
            self.console,
        )

    @classmethod
    def core_size(cls) -> int:
        return SyspageHalStruct.core_size() + struct.calcsize(cls._FMT)


class Syspage:
    def __init__(
        self,
        syspage_start_addr: int = 0,
        syspage_end_addr: int = 0,
        align: int = ALIGN_DEFAULT,
        align_char: bytes = ALIGN_CHAR,
        hal_memory_map_entries: list[tuple[int, int, int]] | None = None,
    ):
        self.commands = {
            "alias": self._cmd_alias,
            "app": self._cmd_app,
            "bankswitch": self._cmd_bankswitch,
            "call": self._cmd_call,
            "console": self._cmd_console,
            "go!": self._cmd_go,
            "kernelimg": self._cmd_kernelimg,
            "map": self._cmd_map,
            "phfs": self._cmd_phfs,
            "wait": self._cmd_wait,
            "dabaabad": self._cmd_dabaabad,
            "\x00": self._cmd_null,
        }
        self._align: int = align
        self._align_char: bytes = align_char
        self._syspage_start_addr: int = syspage_start_addr
        self._syspage_end_addr: int = syspage_end_addr
        self._hal_memory_map_entries = hal_memory_map_entries
        self.syspage_struct = SyspageStruct(
            _syspage_start_addr=self._syspage_start_addr,
            _syspage_end_addr=self._syspage_end_addr,
            _hal_memory_map_entries=self._hal_memory_map_entries,
        )
        self._alias_base_addr: int = 0
        self._aliases: dict[str, tuple[int, int]] = {}

    def parse_plo_scripts(self, pre: Path | None, user1: Path | None, user2: Path | None):
        if pre is not None:
            self.parse_plo_script(pre)
        if user1 is not None:
            self.parse_plo_script(user1)
        if user2 is not None:
            self.parse_plo_script(user2)

    def parse_plo_script(self, script: Path):
        content = self._read_plo_script(script)
        self._parse_content(content)

    def generate_syspage_img(self):
        return self.syspage_struct.pack_align(self._syspage_start_addr, self._align, self._align_char)

    def write_syspage_img_into_target_img(self, img: Path, data: bytes, offset: int) -> None:
        if len(data) > self._syspage_end_addr - self._syspage_start_addr:
            raise OverflowError(
                f"Not enough space for syspage in the image (available space = {self._syspage_end_addr - self._syspage_start_addr}, syspage size = {len(data)})"
            )

        with open(img, "r+b") as f:
            f.seek(offset)
            f.write(pack_align_magic())
            f.write(data)

    def _read_plo_script(self, script: Path):
        with open(script, "r", encoding="ascii", errors="strict") as s:
            return s.read()

    def _parse_content(self, content: str):
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            logging.debug("Parsing: %s", line)

            cmd = line.split()
            if not cmd:
                continue

            cmd_parser = self.commands.get(cmd[0])
            if cmd_parser is None:
                raise ValueError(f"Unsupported command '{cmd[0]}'")
            cmd_parser(cmd)

    def _cmd_alias(self, cmd: list[str]):
        """sets alias to file, usage: alias [-b <base> | [-r] <name> <offset> <size>]"""
        assert len(cmd) in [3, 4, 5], f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"
        if len(cmd) == 3 and cmd[1] == "-b":
            self._alias_base_addr = int(cmd[2], 0)
            return

        if len(cmd) == 4:
            offs = int(cmd[2], 0)
            size = int(cmd[3], 0)
            self._aliases[cmd[1]] = (offs, size)
            return

        if len(cmd) == 5 and cmd[1] == "-r":
            offs = int(cmd[3], 0) + self._alias_base_addr
            size = int(cmd[4], 0)
            self._aliases[cmd[1]] = (offs, size)

    def _cmd_app(self, cmd: list[str]):
        """app - loads app, usage: app [<dev> [-x] <name> <imap1;imap2...> <dmap1;dmap2...>]"""
        assert 5 <= len(cmd) <= 6, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

        dev: bytes = cmd[1].encode("ascii", errors="strict") + b"\x00"

        arg_idx = 2
        flag_exec: bool = False
        if cmd[arg_idx] == "-x":
            flag_exec = True
            arg_idx += 1

        argv = cmd[arg_idx].encode("ascii", errors="strict") + b"\x00"
        name = cmd[arg_idx].split(";")[0]
        imaps = cmd[arg_idx + 1].encode("ascii", errors="strict")
        dmaps = cmd[arg_idx + 2].encode("ascii", errors="strict")

        offs, size = self._aliases[name]

        self.syspage_struct.add_prog(
            map_name=dev,
            offs=offs,
            size=size,
            flag_exec=flag_exec,
            argv=argv,
            imaps=[i + b"\x00" for i in imaps.split(b";")],
            dmaps=[d + b"\x00" for d in dmaps.split(b";")],
        )

    def _cmd_bankswitch(self, cmd: list[str]):
        """bankswitch - switches flash banks, usage: bankswitch [0 | 1]"""
        assert len(cmd) in [1, 2], f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

    def _cmd_call(self, cmd: list[str]):
        """call - calls user's script, usage: call <dev> <script name> <magic>"""
        assert len(cmd) == 4, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

    def _cmd_console(self, cmd: list[str]):
        """console - sets console to device, usage: console <major.minor>"""
        assert len(cmd) > 1, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

    def _cmd_go(self, cmd: list[str]):
        """go! - starts Phoenix-RTOS loaded into memory"""
        assert len(cmd) == 1, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

    def _cmd_kernelimg(self, cmd: list[str]):
        """loads Phoenix-RTOS binary image (only for XIP from read only memory), usage: kernelimg <dev> [name] <text begin> <text size> <data begin> <data size>"""
        assert len(cmd) == 7, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"
        name = cmd[2]
        text_start = int(cmd[3], 16)
        text_size = int(cmd[4], 16)
        data_start = int(cmd[5], 16)
        data_size = int(cmd[6], 16)

        self.syspage_struct.add_entry_into_map(
            text_start, text_start + text_size, SyspageMapEntStruct.EntryType.ALLOCATED
        )
        self.syspage_struct.add_entry_into_map(
            data_start, data_start + data_size, SyspageMapEntStruct.EntryType.ALLOCATED
        )

        self.syspage_struct.pkernel = text_start

    def _cmd_map(self, cmd: list[str]):
        """map - defines multimap, usage: map [<name> <start> <end> <attributes>]"""
        assert len(cmd) == 5, f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"
        start: int = int(cmd[2], 0)
        end: int = int(cmd[3], 0)
        attr: SyspageMapAttr = SyspageMapAttr.from_cmd_str(cmd[4])
        name: bytes = cmd[1].encode("ascii", errors="strict") + b"\x00"
        self.syspage_struct.add_map(start, end, attr, name)

    def _cmd_phfs(self, cmd: list[str]):
        """phfs - registers device in phfs, usage: phfs [<alias> <major.minor> [protocol]]"""
        assert len(cmd) in [3, 4], f"Invalid number of arguments for: {cmd[0]} ({len(cmd)})"

    def _cmd_wait(self, cmd: list[str]):
        """wait - waits in milliseconds or in an infinite loop, usage: wait [ms]"""
        assert len(cmd) in [1, 2]

    def _cmd_dabaabad(self, cmd: list[str]):
        """magic"""
        assert len(cmd) == 1

    def _cmd_null(self, cmd: list[str]):
        """null - end of script"""
        assert len(cmd) == 1
        logging.debug("end of script (null)")

    def _align_addr(self, addr: int, align: int) -> int:
        return (addr + align - 1) & ~(align - 1)


def setup_log():
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")


def arg_parse() -> argparse.Namespace:
    def ensure_file_exist(path: str):
        p = Path(path)
        if not p.is_file():
            raise argparse.ArgumentTypeError(f"File {path} does not exist")
        return p

    parser = argparse.ArgumentParser(description="Generate Phoenix-RTOS syspage image")
    parser.add_argument("--pre", type=ensure_file_exist, required=True, help="Path to plo script")
    parser.add_argument("--user1", type=ensure_file_exist, required=True, help="Path to first user script")
    parser.add_argument("--user2", type=ensure_file_exist, required=False, help="Path to second user script")
    parser.add_argument(
        "--addr",
        type=lambda x: int(x, 0),
        required=False,
        default=-1,
        help="Syspage addr (is needed to calculate pointers) (default: __heap_base)",
    )
    parser.add_argument(
        "--img",
        type=ensure_file_exist,
        required=True,
        help="Path to the image into which syspage will be copied",
    )
    parser.add_argument(
        "--offs",
        type=lambda x: int(x, 0),
        required=False,
        default=0,
        help="Offset for syspage in the image (default: %(default)s)",
    )
    parser.add_argument("--size", type=lambda x: int(x, 0), required=True, help="Max size for syspage in the image")
    parser.add_argument(
        "--elf",
        type=ensure_file_exist,
        required=True,
        help="Path to the elf file from which linker symbols will be retrieved",
    )
    args = parser.parse_args()

    return args


def parse_readelf_output(output: str, symbols_to_find: dict[str, int]):
    hex_chars = set(hexdigits)

    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) < 7 or not parts[0].endswith(":"):
            continue

        address = None
        hex_value = parts[1]
        if hex_value and all(c in hex_chars for c in hex_value):
            address = int(hex_value, 16)
        else:
            continue

        symbol_name = parts[-1]
        if symbol_name in symbols_to_find:
            symbols_to_find[symbol_name] = address


def get_linker_symbol_values_from_elf(elf_path: Path, ld_symbols: list[str]) -> dict[str, int]:
    found_symbols = dict.fromkeys(ld_symbols, 0)

    result = subprocess.run(
        ["readelf", "-sW", elf_path],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )

    parse_readelf_output(result.stdout, found_symbols)

    logging.debug("ld symbols defined in %s", elf_path)
    for k, v in found_symbols.items():
        logging.debug("\t%s: %x", k, v)

    return found_symbols


def make_memory_map_entries(linker_symbols: dict[str, int]) -> list[tuple[int, int, int]]:
    hal_memory_areas = hal_get_memory_areas(linker_symbols)
    hal_memory_map_entries = []
    for i in hal_memory_areas:
        hal_entry = (i[0], i[1], SyspageMapEntStruct.EntryType.TEMP)
        hal_memory_map_entries.append(hal_entry)
    return hal_memory_map_entries


def main():
    setup_log()
    args = arg_parse()

    lsvs = get_linker_symbol_values_from_elf(args.elf, LINKER_SYMBOLS)

    if args.addr == -1:
        args.addr = lsvs["__heap_base"]
        logging.debug("__heap_base = : %s", hex(args.addr))

    syspage = Syspage(
        args.addr,
        args.addr + args.size,
        ALIGN_DEFAULT,
        ALIGN_CHAR,
        make_memory_map_entries(lsvs),
    )
    syspage.parse_plo_scripts(args.pre, args.user1, args.user2)
    syspage.syspage_struct.fill_in_hal_part()
    syspage.write_syspage_img_into_target_img(args.img, syspage.generate_syspage_img(), args.offs)


if __name__ == "__main__":
    main()
