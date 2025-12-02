#!/usr/bin/env python3

# Phoenix-RTOS
#
# Unit tests for generate_syspage.py
#
# Copyright 2025 Phoenix Systems
# Author: Damian Jozwiak
#
# %LICENSE%

import unittest
import struct
from generate_syspage import (
    add_padding_align,
    calc_size_with_align,
    SyspageChar,
    SyspageMapEntStruct,
    SyspageMapStruct,
    SyspageProgStruct,
    SyspageHalStruct,
    SyspageStruct,
    Syspage,
    SyspageMapAttr,
)

NULL_PTR = 0x0

ALIGN = 8
ALIGN_CHAR = b"\xff"

HAL_FMT = "<II" + "II" * 16 + "I" * 16
SP_FMT = HAL_FMT + "IIIII"
MAP_FMT = "<IIIIIIBI"
MAP_ENTTRY_FMT = "<IIBII"
PROG_FMT = "<IIIIIIIII"

HAL_CORE_SIZE = struct.calcsize(HAL_FMT)
SP_CORE_SIZE = HAL_CORE_SIZE + struct.calcsize("<IIIII")
MAP_CORE_SIZE = struct.calcsize(MAP_FMT)
MAP_ENTRY_CORE_SIZE = struct.calcsize(MAP_ENTTRY_FMT)
PROG_CORE_SIZE = struct.calcsize(PROG_FMT)


# helpers
def size_with_padding(size: int, align: int = ALIGN) -> int:
    return (size + (align - 1)) & ~(align - 1)


def padding_len(size: int, align: int = ALIGN) -> int:
    return (-size) % align


def pack_main(size, pkernel, map_ptr, prog_ptr, console, align=ALIGN, align_char=ALIGN_CHAR):
    return struct.pack("<IIIII", size, pkernel, map_ptr, prog_ptr, console) + align_char * padding_len(
        SP_CORE_SIZE, align
    )


def pack_map(
    next_ptr,
    prev_ptr,
    entries_ptr,
    start_addr,
    end_addr,
    attr,
    map_id,
    name_ptr,
    align_char=ALIGN_CHAR,
    align=ALIGN,
):
    return struct.pack(
        "<IIIIIIBI",
        next_ptr,
        prev_ptr,
        entries_ptr,
        start_addr,
        end_addr,
        attr,
        map_id,
        name_ptr,
    ) + align_char * padding_len(MAP_CORE_SIZE, align)


def pack_map_entry(next_ptr, prev_ptr, entry_type, start_addr, end_addr, align=ALIGN, align_char=ALIGN_CHAR):
    return struct.pack("<IIBII", next_ptr, prev_ptr, entry_type, start_addr, end_addr) + align_char * padding_len(
        MAP_ENTRY_CORE_SIZE, align
    )


def pack_prog(
    next_ptr,
    prev_ptr,
    start_addr,
    end_addr,
    argv_ptr,
    imap_sz,
    imaps_ptr,
    dmap_sz,
    dmaps_ptr,
    align_char=ALIGN_CHAR,
    align=ALIGN,
):
    return struct.pack(
        "<IIIIIIIII",
        next_ptr,
        prev_ptr,
        start_addr,
        end_addr,
        argv_ptr,
        imap_sz,
        imaps_ptr,
        dmap_sz,
        dmaps_ptr,
    ) + align_char * padding_len(PROG_CORE_SIZE, align)


def make_syspage_char(data: bytes, addr: int = 0, align: int = ALIGN, align_char: bytes = ALIGN_CHAR):
    syspage_char = SyspageChar(data=data)
    pack_data = syspage_char.pack_align(addr, align, align_char)
    align_size = syspage_char.pack_align_size(addr, align)
    return syspage_char, pack_data, align_size


def make_c_string(s: str):
    return bytes(s + "\0", encoding="ascii", errors="strict")


class TestAddPaddingAlign(unittest.TestCase):
    def test_add_padding_align_with_defaults(self):
        """default alignment 8 and padding character 0x00"""
        # Arrange
        test_cases = {
            "single_byte": (b"\xab", b"\xab" + b"\x00" * 7),
            "already_aligned": (b"\xab" * 8, b"\xab" * 8),
            "almost_aligned": (b"\xab" * 7, b"\xab" * 7 + b"\x00"),
            "over_aligned": (b"\xab" * 9, b"\xab" * 9 + b"\x00" * 7),
            "empty_data": (b"", b""),
        }

        for name, (data, ex_data) in test_cases.items():
            with self.subTest(case=name):
                # Act
                actual_data = add_padding_align(data)

                # Assert
                self.assertEqual(
                    actual_data,
                    ex_data,
                    f"case={name} act_len={len(actual_data)} exp_len={len(ex_data)}",
                )

    def test_add_padding_align_with_empty_data(self):
        # Arrange
        align = 8
        align_char = ALIGN_CHAR
        data = b""

        test_cases = {
            "aligned_addr_zero": (0x0, b""),
            "aligned_addr_non_zero": (0x100, b""),
            "not_aligned_addr_corner_case_max": (0x101, align_char * 7),
            "not_aligned_addr": (0x103, align_char * 5),
            "not_aligned_addr_corner_case_min": (0x107, align_char),
        }

        for name, (addr, ex_data) in test_cases.items():
            with self.subTest(case=name, addr=addr):
                # Act
                actual_data = add_padding_align(data, addr, align, align_char)

                # Assert
                self.assertEqual(
                    actual_data,
                    ex_data,
                    f"case={name} addr=0x{addr:x} act_len={len(actual_data)} exp_len={len(ex_data)}",
                )

    def test_add_padding_aligna_with_aligned_addr(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR

        test_cases = {
            "len1": (b"\x12", b"\x12" + align_char * 7),
            "len3": (b"\x12" * 3, b"\x12" * 3 + align_char * 5),
            "len9": (b"\x12" * 9, b"\x12" * 9 + align_char * 7),
        }

        for name, (data, expected) in test_cases.items():
            with self.subTest(case=name):
                # Act
                actual = add_padding_align(data, addr, align, align_char)

                # Assert
                self.assertEqual(
                    actual,
                    expected,
                    f"case={name} act_len={len(actual)} exp_len={len(expected)}",
                )
                self.assertEqual(len(actual) % align, 0, f"case={name} not aligned to {align}")

    def test_add_padding_align_with_not_aligned_addr(self):
        # Arrange
        align = 8
        align_char = b"\xff"
        test_cases = {
            "addr_0xA101_len1": (0xA101, b"\x12", b"\x12" + align_char * 6),
            "addr_0xB104_len2": (0xB104, b"\x12" * 2, b"\x12" * 2 + align_char * 2),
            "addr_0xC107_len8": (0xC107, b"\x12" * 8, b"\x12" * 8 + align_char),
            "addr_0xD107_len9": (0xD107, b"\x12" * 9, b"\x12" * 9),
            "addr_0xE107_len10": (0xE107, b"\x12" * 10, b"\x12" * 10 + align_char * 7),
        }

        for name, (addr, data, expected) in test_cases.items():
            with self.subTest(case=name, addr=addr, data_len=len(data)):
                # Act
                actual = add_padding_align(data, addr, align, align_char)

                # Assert
                self.assertEqual(
                    actual,
                    expected,
                    f"case={name} addr=0x{addr:x} exp_len={len(expected)} "
                    f"act_len={len(actual)} end=0x{addr + len(actual):x} "
                    f"pad_len={len(actual) - len(data)}",
                )


class TestCalcSizeWithAlign(unittest.TestCase):
    def test_calc_size_with_align(self):
        # Arrange
        align = ALIGN
        test_cases = {
            "len0_addr_aligned": (0x100, 0, 0),
            "len0_addr_0x103": (0x103, 0, 5),
            "len1_addr_aligned": (0x100, 1, 8),
            "len1_addr_0x103": (0x103, 1, 5),
            "len9_addr_aligned": (0x100, 9, 16),
            "len8_addr_0x107": (0x107, 8, 9),
            "len9_addr_0x107": (0x107, 9, 9),
            "len10_addr_0x107": (0x107, 10, 17),
        }

        for name, (addr, data_len, expected) in test_cases.items():
            with self.subTest(case=name, addr=addr, data_len=data_len):
                # Act
                actual = calc_size_with_align(data_len, addr, align)

                # Assert
                self.assertEqual(
                    actual,
                    expected,
                    f"case={name} addr=0x{addr:x} data_len={data_len} act={actual} exp={expected}",
                )


class TestSyspageChar(unittest.TestCase):
    def setUp(self):
        self.addr = 0x100
        self.align = ALIGN
        self.align_char = ALIGN_CHAR

    def test_SyspageChar_default_empty(self):
        # Arrange
        syspage_char = SyspageChar()

        ex_size = 0
        ex_data = b""

        # Act
        actual_size = syspage_char.pack_align_size(self.addr, self.align)
        actual_data = syspage_char.pack_align(self.addr, self.align, self.align_char)

        # Assert
        self.assertEqual(actual_size, ex_size)
        self.assertEqual(actual_data, ex_data)

    def test_SyspageChar(self):
        # Arrange
        test_cases = {
            "single_byte": b"a",
            "typical_string": b"abc",
            "almost_aligned": b"x" * 7,
            "perfectly_aligned": b"y" * 8,
            "just_over_aligned": b"z" * 9,
            "typical_string_with_null": b"test string\0",
        }

        for name, data in test_cases.items():
            with self.subTest(case=name, data_len=len(data)):
                # Arrange
                syspage_char = SyspageChar(data=data)
                ex_size = size_with_padding(len(data), self.align)
                ex_data = data + padding_len(len(data), self.align) * self.align_char

                # Act
                actual_size = syspage_char.pack_align_size(self.addr, self.align)
                actual_data = syspage_char.pack_align(self.addr, self.align, self.align_char)

                # Assert
                self.assertEqual(
                    actual_size,
                    ex_size,
                    f"case={name}: mismatch in size",
                )
                self.assertEqual(
                    actual_data,
                    ex_data,
                    f"case={name}: mismatch in binary data",
                )


class TestSyspageMapEntStruct(unittest.TestCase):
    def test_pack_and_size(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR

        next_ptr = 0x00000100
        prev_ptr = 0x00000200
        entry_type = SyspageMapEntStruct.EntryType.INVALID
        start_addr = 0x00006000
        end_addr = 0x00008000

        test_params = {
            "default_empty": {
                "instance": SyspageMapEntStruct(),
                "ex_core_data": b"\x00" * MAP_ENTRY_CORE_SIZE + align_char * padding_len(MAP_ENTRY_CORE_SIZE, align),
            },
            "with_data": {
                "instance": SyspageMapEntStruct(next_ptr, prev_ptr, entry_type, start_addr, end_addr),
                "ex_core_data": pack_map_entry(next_ptr, prev_ptr, entry_type, start_addr, end_addr),
            },
        }

        for name, params in test_params.items():
            with self.subTest(case=name):
                # Arrange
                map_entry_struct = params["instance"]
                ex_core_size = MAP_ENTRY_CORE_SIZE
                ex_align_size = size_with_padding(MAP_ENTRY_CORE_SIZE, align)
                ex_data = params["ex_core_data"]

                # Act
                actual_core_size = map_entry_struct.core_size()
                actual_align_size = map_entry_struct.pack_align_size(addr, align)
                actual_data = map_entry_struct.pack_align(addr, align, align_char)

                # Assert
                self.assertEqual(actual_core_size, ex_core_size, f"case={name}: core size mismatch")
                self.assertEqual(actual_align_size, ex_align_size, f"case={name}: aligned size mismatch")
                self.assertEqual(actual_data, ex_data, f"case={name}: packed data mismatch")


class TestSyspageMapStruct(unittest.TestCase):
    def test_are_entries_overlapping(self):
        # Arrange

        map_params = {
            "next_ptr": 0,
            "prev_ptr": 0,
            "start_addr": 0x00000000,
            "end_addr": 0x10000000,
            "attr": 0x2,
            "map_id": 0x1,
        }

        start_entry = 0x500
        end_entry = 0x1000

        # [start, stop, expected]
        test_cases = (
            [0x100, 0x200, False],
            [0x400, 0x600, True],
            [0x700, 0x800, True],
            [0x900, 0x1100, True],
            [0x1200, 0x1300, False],
            [0x100, 0x1300, True],
        )

        # Act
        m = SyspageMapStruct(**map_params)
        m.add_entry(start_entry, end_entry)

        for start, end, ex in test_cases:
            with self.subTest():
                # Act
                actual = m.are_entries_overlapping(start, end)

                # Assert
                self.assertEqual(actual, ex)

    def test_pack_and_size(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR

        map_params_empty = {
            "next_ptr": 0x0,
            "prev_ptr": 0x0,
            "start_addr": 0x0,
            "end_addr": 0x0,
            "attr": SyspageMapAttr.READ,
            "map_id": 0x0,
        }

        map_params = {
            "next_ptr": 0x00010000,
            "prev_ptr": 0x00020000,
            "start_addr": 0x00001000,
            "end_addr": 0x00004000,
            "attr": SyspageMapAttr.WRITE,
            "map_id": 0x1,
        }

        entry_params_1 = {
            "start_addr": 0x00001100,
            "end_addr": 0x00001200,
            "entry_type": SyspageMapEntStruct.EntryType.ALLOCATED,
        }

        entry_params_2 = {
            "start_addr": 0x00001300,
            "end_addr": 0x00001400,
            "entry_type": SyspageMapEntStruct.EntryType.INVALID,
        }

        entry_params_3 = {
            "start_addr": 0x00001400,
            "end_addr": 0x00001600,
            "entry_type": SyspageMapEntStruct.EntryType.RESERVED,
        }

        map_name, ex_map_name_data, ex_map_name_align_size = make_syspage_char(b"name_name", addr, align, align_char)

        # calculation of pointers
        ex_addr_name = addr + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_entries = ex_addr_name + ex_map_name_align_size
        ex_addr_entries_1 = ex_addr_entries
        ex_addr_entries_2 = ex_addr_entries_1 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_entries_3 = ex_addr_entries_2 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_entries_next_1 = ex_addr_entries_2
        ex_addr_entries_prev_1 = ex_addr_entries_3
        ex_addr_entries_next_2 = ex_addr_entries_3
        ex_addr_entries_prev_2 = ex_addr_entries_1
        ex_addr_entries_next_3 = ex_addr_entries_1
        ex_addr_entries_prev_3 = ex_addr_entries_2

        # preparation of test structures
        map_default_empty = SyspageMapStruct()

        map_basic = SyspageMapStruct(**map_params)

        map_only_with_name = SyspageMapStruct(**map_params, name=map_name)

        map_with_one_entry = SyspageMapStruct(**map_params, name=map_name)
        map_with_one_entry.add_entry(**entry_params_1)

        map_with_multiple_entries = SyspageMapStruct(**map_params, name=map_name)
        map_with_multiple_entries.add_entry(**entry_params_1)
        map_with_multiple_entries.add_entry(**entry_params_2)
        map_with_multiple_entries.add_entry(**entry_params_3)

        #  expected test data preparation
        test_cases = {
            "default_empty": {
                "instance": map_default_empty,
                "ex_align_size": size_with_padding(MAP_CORE_SIZE, align),
                "ex_data": (pack_map(**map_params_empty, entries_ptr=NULL_PTR, name_ptr=NULL_PTR)),
            },
            "basic": {
                "instance": map_basic,
                "ex_align_size": size_with_padding(MAP_CORE_SIZE, align),
                "ex_data": (pack_map(**map_params, entries_ptr=NULL_PTR, name_ptr=NULL_PTR)),
            },
            "only_with_name": {
                "instance": map_only_with_name,
                "ex_align_size": size_with_padding(MAP_CORE_SIZE, align) + ex_map_name_align_size,
                "ex_data": (pack_map(**map_params, entries_ptr=NULL_PTR, name_ptr=ex_addr_name) + ex_map_name_data),
            },
            "with_one_entry": {
                "instance": map_with_one_entry,
                "ex_align_size": (
                    size_with_padding(MAP_CORE_SIZE, align)
                    + ex_map_name_align_size
                    + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
                ),
                "ex_data": (
                    pack_map(**map_params, entries_ptr=ex_addr_entries, name_ptr=ex_addr_name)
                    + ex_map_name_data
                    + pack_map_entry(
                        **entry_params_1,
                        next_ptr=ex_addr_entries,
                        prev_ptr=ex_addr_entries,
                    )
                ),
            },
            "with_multiple_entries": {
                "instance": map_with_multiple_entries,
                "ex_align_size": (
                    size_with_padding(MAP_CORE_SIZE, align)
                    + ex_map_name_align_size
                    + size_with_padding(MAP_ENTRY_CORE_SIZE, align) * 3
                ),
                "ex_data": (
                    pack_map(**map_params, entries_ptr=ex_addr_entries, name_ptr=ex_addr_name)
                    + ex_map_name_data
                    + pack_map_entry(
                        **entry_params_1,
                        next_ptr=ex_addr_entries_next_1,
                        prev_ptr=ex_addr_entries_prev_1,
                    )
                    + pack_map_entry(
                        **entry_params_2,
                        next_ptr=ex_addr_entries_next_2,
                        prev_ptr=ex_addr_entries_prev_2,
                    )
                    + pack_map_entry(
                        **entry_params_3,
                        next_ptr=ex_addr_entries_next_3,
                        prev_ptr=ex_addr_entries_prev_3,
                    )
                ),
            },
        }

        for name, params in test_cases.items():
            with self.subTest(case=name):
                # Arrange
                syspage_map_struct = params["instance"]

                # Act
                actual_core_size = syspage_map_struct.core_size()
                actual_align_size = syspage_map_struct.pack_align_size(addr, align)
                actual_data = syspage_map_struct.pack_align(addr, align, align_char)

                # Assert
                self.assertEqual(actual_core_size, MAP_CORE_SIZE, f"case={name}: core size mismatch")
                self.assertEqual(
                    actual_align_size,
                    params["ex_align_size"],
                    f"case={name}: aligned size mismatch",
                )
                self.assertEqual(actual_data, params["ex_data"], f"case={name}: packed data mismatch")


class TestSyspageProgStruct(unittest.TestCase):
    def test_pack_and_size(self):
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR

        prog_params = {
            "next_ptr": 0x00030000,
            "prev_ptr": 0x00010000,
            "start_addr": 0x00000400,
            "end_addr": 0x00000600,
            "imap_sz": 0x2,
            "dmap_sz": 0x4,
        }

        argv, ex_argv_data, ex_argv_align_size = make_syspage_char(b"argv;abc;def;ghj;123", addr, align, align_char)
        imaps, ex_imaps_data, ex_imaps_align_size = make_syspage_char(b"\x01\x02", addr, align, align_char)
        dmaps, ex_dmaps_data, ex_dmaps_align_size = make_syspage_char(b"\x03\x04\x05\x06", addr, align, align_char)

        # calculation of pointers
        ex_addr_argv = addr + size_with_padding(PROG_CORE_SIZE, align)
        ex_addr_imap = ex_addr_argv + ex_argv_align_size
        ex_addr_dmap = ex_addr_imap + ex_imaps_align_size

        # preparation of test structures
        prog_default_empty = SyspageProgStruct()
        prog_basic = SyspageProgStruct(**prog_params)
        prog_with_args = SyspageProgStruct(**prog_params, argv=argv, imaps=imaps, dmaps=dmaps)

        # expected test data preparation
        test_cases = {
            "default_empty": {
                "instance": prog_default_empty,
                "ex_align_size": size_with_padding(PROG_CORE_SIZE, align),
                "ex_data": b"\x00" * PROG_CORE_SIZE + align_char * padding_len(PROG_CORE_SIZE, align),
            },
            "basic": {
                "instance": prog_basic,
                "ex_align_size": size_with_padding(PROG_CORE_SIZE, align),
                "ex_data": (pack_prog(**prog_params, argv_ptr=NULL_PTR, imaps_ptr=NULL_PTR, dmaps_ptr=NULL_PTR)),
            },
            "with_args": {
                "instance": prog_with_args,
                "ex_align_size": (
                    size_with_padding(PROG_CORE_SIZE, align)
                    + ex_argv_align_size
                    + ex_imaps_align_size
                    + ex_dmaps_align_size
                ),
                "ex_data": (
                    pack_prog(
                        **prog_params,
                        argv_ptr=ex_addr_argv,
                        imaps_ptr=ex_addr_imap,
                        dmaps_ptr=ex_addr_dmap,
                    )
                    + ex_argv_data
                    + ex_imaps_data
                    + ex_dmaps_data
                ),
            },
        }

        for name, params in test_cases.items():
            with self.subTest(case=name):
                # Arrange
                syspage_prog_struct = params["instance"]

                # Act
                actual_core_size = syspage_prog_struct.core_size()
                actual_align_size = syspage_prog_struct.pack_align_size(addr, align)
                actual_data = syspage_prog_struct.pack_align(addr, align, align_char)

                # Assert
                self.assertEqual(actual_core_size, PROG_CORE_SIZE, f"case={name}: core size mismatch")
                self.assertEqual(
                    actual_align_size,
                    params["ex_align_size"],
                    f"case={name}: aligned size mismatch",
                )
                self.assertEqual(actual_data, params["ex_data"], f"case={name}: packed data mismatch")


class TestSyspageStructNoLinkerSymbols(unittest.TestCase):
    def test_pack_and_size(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR
        syspage_hal_struct = SyspageHalStruct()

        syspage_struct_params = {"pkernel": 0x00400000, "console": 0x1}

        map_start_addr = 0x00001000
        map_end_addr = 0x0000004000
        map_attr = SyspageMapAttr.WRITE
        map_raw_name = b"map_1\x00"

        prog_offs = 0x00000200
        prog_size = 0x00000600
        prog_flag_exec = True
        prog_raw_name = b"prog_1;arg1;arg2\x00"

        ex_map_id = 0x0  # maps are numbered from zero
        _, ex_map_name_data, ex_map_name_align_size = make_syspage_char(map_raw_name, addr, align, align_char)

        ex_prog_start_addr = map_start_addr + prog_offs
        ex_prog_end_addr = ex_prog_start_addr + prog_size

        # "X" added because flag_exec=True
        _, ex_prog_argv_data, ex_prog_argv_align_size = make_syspage_char(b"X" + prog_raw_name, addr, align, align_char)

        ex_prog_imaps, ex_prog_imaps_data, ex_prog_imaps_align_size = make_syspage_char(
            bytes([ex_map_id]), addr, align, align_char
        )
        ex_prog_imap_sz = len(ex_prog_imaps.data)

        ex_prog_dmaps, ex_prog_dmaps_data, ex_prog_dmaps_align_size = make_syspage_char(
            bytes([ex_map_id]), addr, align, align_char
        )
        ex_prog_dmap_sz = len(ex_prog_dmaps.data)

        ex_map_entry_start_addr = ex_prog_start_addr
        ex_map_entry_end_addr = ex_prog_end_addr
        ex_map_entry_type = SyspageMapEntStruct.EntryType.ALLOCATED

        # calculation of pointers
        ex_addr_map = addr + size_with_padding(SP_CORE_SIZE, align)
        ex_addr_map_name = ex_addr_map + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_entry = ex_addr_map_name + ex_map_name_align_size
        ex_addr_prog = ex_addr_map_entry + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_prog_argv = ex_addr_prog + size_with_padding(PROG_CORE_SIZE, align)
        ex_addr_prog_imap = ex_addr_prog_argv + ex_prog_argv_align_size
        ex_addr_prog_dmap = ex_addr_prog_imap + ex_prog_imaps_align_size

        # preparation of test structures
        syspage_struct_empty = SyspageStruct()

        syspage_struct_basic = SyspageStruct(**syspage_struct_params)

        syspage_struct_with_map_and_prog = SyspageStruct(**syspage_struct_params)
        syspage_struct_with_map_and_prog.add_map(map_start_addr, map_end_addr, map_attr, map_raw_name)
        syspage_struct_with_map_and_prog.add_prog(
            map_raw_name,
            prog_offs,
            prog_size,
            prog_flag_exec,
            prog_raw_name,
            [map_raw_name],
            [map_raw_name],
        )

        # expected test data preparation
        ex_align_size_with_map_and_prog = (
            size_with_padding(SP_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_align_size
            + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
            + size_with_padding(PROG_CORE_SIZE, align)
            + ex_prog_argv_align_size
            + ex_prog_imaps_align_size
            + ex_prog_dmaps_align_size
        )

        map_params = {
            "next_ptr": ex_addr_map,
            "prev_ptr": ex_addr_map,
            "entries_ptr": ex_addr_map_entry,
            "start_addr": map_start_addr,
            "end_addr": map_end_addr,
            "attr": map_attr,
            "map_id": ex_map_id,
            "name_ptr": ex_addr_map_name,
        }

        entry_params = {
            "next_ptr": ex_addr_map_entry,
            "prev_ptr": ex_addr_map_entry,
            "entry_type": ex_map_entry_type,
            "start_addr": ex_map_entry_start_addr,
            "end_addr": ex_map_entry_end_addr,
        }

        prog_params = {
            "next_ptr": ex_addr_prog,
            "prev_ptr": ex_addr_prog,
            "start_addr": ex_prog_start_addr,
            "end_addr": ex_prog_end_addr,
            "argv_ptr": ex_addr_prog_argv,
            "imap_sz": ex_prog_imap_sz,
            "imaps_ptr": ex_addr_prog_imap,
            "dmap_sz": ex_prog_dmap_sz,
            "dmaps_ptr": ex_addr_prog_dmap,
        }

        test_cases = {
            "default_empty": {
                "instance": syspage_struct_empty,
                "ex_align_size": size_with_padding(SP_CORE_SIZE, align),
                "ex_data": (
                    syspage_hal_struct.pack()
                    + pack_main(
                        size_with_padding(SP_CORE_SIZE, align),
                        NULL_PTR,
                        NULL_PTR,
                        NULL_PTR,
                        0,
                    )
                ),
            },
            "basic": {
                "instance": syspage_struct_basic,
                "ex_align_size": size_with_padding(SP_CORE_SIZE, align),
                "ex_data": (
                    syspage_hal_struct.pack()
                    + pack_main(
                        **syspage_struct_params,
                        size=size_with_padding(SP_CORE_SIZE, align),
                        map_ptr=NULL_PTR,
                        prog_ptr=NULL_PTR,
                    )
                ),
            },
            "with_map_and_prog": {
                "instance": syspage_struct_with_map_and_prog,
                "ex_align_size": ex_align_size_with_map_and_prog,
                "ex_data": (
                    syspage_hal_struct.pack()
                    + pack_main(
                        **syspage_struct_params,
                        size=ex_align_size_with_map_and_prog,
                        map_ptr=ex_addr_map,
                        prog_ptr=ex_addr_prog,
                    )
                    + pack_map(**map_params)
                    + ex_map_name_data
                    + pack_map_entry(**entry_params)
                    + pack_prog(**prog_params)
                    + ex_prog_argv_data
                    + ex_prog_imaps_data
                    + ex_prog_dmaps_data
                ),
            },
        }

        for name, params in test_cases.items():
            with self.subTest(case=name):
                # Arrange
                syspage_struct = params["instance"]

                # Act
                actual_core_size = syspage_struct.core_size()
                actual_align_size = syspage_struct.pack_align_size(addr, align)
                actual_data = syspage_struct.pack_align(addr, align, align_char)
                # Assert
                self.assertEqual(actual_core_size, SP_CORE_SIZE, f"case={name}: core size mismatch")
                self.assertEqual(
                    actual_align_size,
                    params["ex_align_size"],
                    f"case={name}: aligned size mismatch",
                )
                self.assertEqual(actual_data, params["ex_data"], f"case={name}: packed data mismatch")


class TestSyspageEntries(unittest.TestCase):
    def test_syspage_entries_search(self):
        # Arrange
        syspage_map_struct = SyspageMapStruct()
        start_addr = 0x300
        end_addr = 0x900

        memory_areas = [
            (0xA00, 0xB00, SyspageMapEntStruct.EntryType.TEMP),
            (0x800, 0xA00, SyspageMapEntStruct.EntryType.TEMP),
            (0x600, 0x700, SyspageMapEntStruct.EntryType.INVALID),
            (0x500, 0x600, SyspageMapEntStruct.EntryType.ALLOCATED),
            (0x200, 0x400, SyspageMapEntStruct.EntryType.RESERVED),
            (0x100, 0x200, SyspageMapEntStruct.EntryType.TEMP),
        ]

        ex_etries = [
            (0x300, 0x400, SyspageMapEntStruct.EntryType.RESERVED),
            (0x500, 0x600, SyspageMapEntStruct.EntryType.ALLOCATED),
            (0x600, 0x700, SyspageMapEntStruct.EntryType.INVALID),
            (0x800, 0x900, SyspageMapEntStruct.EntryType.TEMP),
        ]

        # Act
        actual_entries = syspage_map_struct._get_entries(start_addr, end_addr, memory_areas)

        # Assert
        self.assertEqual(actual_entries, ex_etries)


class TestCmdMap(unittest.TestCase):
    def test_cmd_map(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR

        ld_symbols = {
            "__init_start": 0x20000100,
            "__init_end": 0x20000200,
            "__text_start": 0x20000300,
            "__etext": 0x20000400,
            "__rodata_start": 0x20000500,
            "__rodata_end": 0x20000600,
            "__init_array_start": 0x20000700,
            "__init_array_end": 0x20000800,
            "__fini_array_start": 0,
            "__fini_array_end": 0,
            "__ramtext_start": 0,
            "__ramtext_end": 0,
            "__data_start": 0,
            "__data_end": 0,
            "__bss_start": 0,
            "__bss_end": 0,
            "__heap_base": 0,
            "__heap_limit": 0,
            "__stack_limit": 0,
            "__stack_top": 0,
        }

        memory_areas = [
            (ld_symbols["__init_start"], ld_symbols["__init_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__text_start"], ld_symbols["__etext"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__rodata_start"], ld_symbols["__rodata_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__init_array_start"], ld_symbols["__init_array_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__fini_array_start"], ld_symbols["__fini_array_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__ramtext_start"], ld_symbols["__ramtext_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__data_start"], ld_symbols["__data_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__bss_start"], ld_symbols["__bss_end"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__heap_base"], ld_symbols["__heap_limit"], SyspageMapEntStruct.EntryType.TEMP),
            (ld_symbols["__stack_limit"], ld_symbols["__stack_top"], SyspageMapEntStruct.EntryType.TEMP),
        ]

        syspage = Syspage(addr, addr + 0x200, align, align_char, hal_memory_map_entries=memory_areas)
        syspage_hal_struct = SyspageHalStruct()
        cmds = (
            "map flash0 0x08000000 0x08080000 rx\n"
            "map flash1 0x08080000 0x08100000 rx\n"
            "map ram 0x20000000 0x20050000 rwx\n"
        )
        words = dict(
            zip(
                [
                    "cmd1",
                    "name1",
                    "start1",
                    "end1",
                    "attr1",
                    "cmd2",
                    "name2",
                    "start2",
                    "end2",
                    "attr2",
                    "cmd3",
                    "name3",
                    "start3",
                    "end3",
                    "attr3",
                ],
                cmds.split(),
            )
        )

        _, ex_map_name_1_data, ex_map_name_1_align_size = make_syspage_char(
            make_c_string(words["name1"]), addr, align, align_char
        )

        _, ex_map_name_2_data, ex_map_name_2_align_size = make_syspage_char(
            make_c_string(words["name2"]), addr, align, align_char
        )

        _, ex_map_name_3_data, ex_map_name_3_align_size = make_syspage_char(
            make_c_string(words["name3"]), addr, align, align_char
        )

        ex_align_size = (
            size_with_padding(SP_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_1_align_size
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_2_align_size
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_3_align_size
            + 4 * size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        )

        ex_attr1 = 1 | 4
        ex_attr2 = 1 | 4
        ex_attr3 = 1 | 2 | 4

        ex_id_1 = 0
        ex_id_2 = 1
        ex_id_3 = 2

        ex_entry_type = SyspageMapEntStruct.EntryType.TEMP

        # calculation of pointers
        ex_addr_map_1 = addr + size_with_padding(SP_CORE_SIZE, align)
        ex_addr_map_name_1 = ex_addr_map_1 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_2 = ex_addr_map_name_1 + ex_map_name_1_align_size
        ex_addr_map_name_2 = ex_addr_map_2 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_3 = ex_addr_map_name_2 + ex_map_name_2_align_size
        ex_addr_map_name_3 = ex_addr_map_3 + size_with_padding(MAP_CORE_SIZE, align)

        ex_addr_map_entry_3_1 = ex_addr_map_name_3 + ex_map_name_3_align_size
        ex_addr_map_entry_3_2 = ex_addr_map_entry_3_1 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_entry_3_3 = ex_addr_map_entry_3_2 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_entry_3_4 = ex_addr_map_entry_3_3 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)

        # expected test data preparation
        ex_data = (
            syspage_hal_struct.pack()
            + pack_main(
                ex_align_size,
                0,
                ex_addr_map_1,
                0,
                0,
            )
            + pack_map(
                ex_addr_map_2,
                ex_addr_map_3,
                0x00000000,
                int(words["start1"], 0),
                int(words["end1"], 0),
                ex_attr1,
                ex_id_1,
                ex_addr_map_name_1,
            )
            + ex_map_name_1_data
            + pack_map(
                ex_addr_map_3,
                ex_addr_map_1,
                0x00000000,
                int(words["start2"], 0),
                int(words["end2"], 0),
                ex_attr2,
                ex_id_2,
                ex_addr_map_name_2,
            )
            + ex_map_name_2_data
            + pack_map(
                ex_addr_map_1,
                ex_addr_map_2,
                ex_addr_map_entry_3_1,
                int(words["start3"], 0),
                int(words["end3"], 0),
                ex_attr3,
                ex_id_3,
                ex_addr_map_name_3,
            )
            + ex_map_name_3_data
            + (
                pack_map_entry(
                    ex_addr_map_entry_3_2,
                    ex_addr_map_entry_3_4,
                    ex_entry_type,
                    ld_symbols["__init_start"],
                    ld_symbols["__init_end"],
                )
                + pack_map_entry(
                    ex_addr_map_entry_3_3,
                    ex_addr_map_entry_3_1,
                    ex_entry_type,
                    ld_symbols["__text_start"],
                    ld_symbols["__etext"],
                )
                + pack_map_entry(
                    ex_addr_map_entry_3_4,
                    ex_addr_map_entry_3_2,
                    ex_entry_type,
                    ld_symbols["__rodata_start"],
                    ld_symbols["__rodata_end"],
                )
                + pack_map_entry(
                    ex_addr_map_entry_3_1,
                    ex_addr_map_entry_3_3,
                    ex_entry_type,
                    ld_symbols["__init_array_start"],
                    ld_symbols["__init_array_end"],
                )
            )
        )

        # Act
        syspage._parse_content(cmds)
        actual_data = syspage.generate_syspage_img()

        # Assert
        self.assertEqual(actual_data, ex_data)


class TestCmdAliasAndApp(unittest.TestCase):
    def test_cmd_alias_and_app(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR
        syspage = Syspage(addr, addr + 0x200, align, align_char)
        syspage_hal_struct = SyspageHalStruct()
        cmds = (
            "map flash0 0x08000000 0x08080000 rx\n"
            "map flash1 0x08080000 0x08100000 rx\n"
            "map ram 0x20000000 0x20050000 rwx\n"
            "alias metersrv-usnd 0x16400 0x14764\n"
            "app flash0 -x metersrv-usnd;944f2d86f0ed016191fd2b7493fc00f3 flash0 ram\n"
            "alias stm32l4-multi 0x2ac00 0x9f80\n"
            "app flash0 -x stm32l4-multi flash0 ram\n"
            "alias cosemsrv 0x34c00 0x48e24\n"
            "app flash0 -x cosemsrv flash0 ram\n"
        )

        words = dict(
            zip(
                [
                    "cmd1",
                    "name1",
                    "start1",
                    "end1",
                    "attr1",
                    "cmd2",
                    "name2",
                    "start2",
                    "end2",
                    "attr2",
                    "cmd3",
                    "name3",
                    "start3",
                    "end3",
                    "attr3",
                    "cmd4",
                    "name4",
                    "offs4",
                    "size4",
                    "cmd5",
                    "dev5",
                    "flag5",
                    "name5",
                    "imap5",
                    "dmap5",
                    "cmd6",
                    "name6",
                    "offs6",
                    "size6",
                    "cmd7",
                    "dev7",
                    "flag7",
                    "name7",
                    "imap7",
                    "dmap7",
                    "cmd8",
                    "name8",
                    "offs8",
                    "size8",
                    "cmd9",
                    "dev9",
                    "flag9",
                    "name9",
                    "imap9",
                    "dmap9",
                ],
                cmds.split(),
            )
        )

        ex_id_flash0 = 0  # flash0
        ex_id_flash1 = 1  # flash1
        ex_id_ram = 2  # ram

        _, ex_map_name_1_data, ex_map_name_1_align_size = make_syspage_char(
            make_c_string(words["name1"]), addr, align, align_char
        )
        _, ex_map_name_2_data, ex_map_name_2_align_size = make_syspage_char(
            make_c_string(words["name2"]), addr, align, align_char
        )
        _, ex_map_name_3_data, ex_map_name_3_align_size = make_syspage_char(
            make_c_string(words["name3"]), addr, align, align_char
        )
        _, ex_prog_argv_1_data, ex_prog_argv_1_align_size = make_syspage_char(
            make_c_string("X" + words["name5"]), addr, align, align_char
        )
        ex_prog_imaps_1, ex_prog_imaps_1_data, ex_prog_imaps_1_align_size = make_syspage_char(
            bytes([ex_id_flash0]), addr, align, align_char
        )
        ex_prog_dmaps_1, ex_prog_dmaps_1_data, ex_prog_dmaps_1_align_size = make_syspage_char(
            bytes([ex_id_ram]), addr, align, align_char
        )
        _, ex_prog_argv_2_data, ex_prog_argv_2_align_size = make_syspage_char(
            make_c_string("X" + words["name7"]), addr, align, align_char
        )
        ex_prog_imaps_2, ex_prog_imaps_2_data, ex_prog_imaps_2_align_size = make_syspage_char(
            bytes([ex_id_flash0]), addr, align, align_char
        )
        ex_prog_dmaps_2, ex_prog_dmaps_2_data, ex_prog_dmaps_2_align_size = make_syspage_char(
            bytes([ex_id_ram]), addr, align, align_char
        )
        _, ex_prog_argv_3_data, ex_prog_argv_3_align_size = make_syspage_char(
            make_c_string("X" + words["name9"]), addr, align, align_char
        )
        ex_prog_imaps_3, ex_prog_imaps_3_data, ex_prog_imaps_3_align_size = make_syspage_char(
            bytes([ex_id_flash0]), addr, align, align_char
        )
        ex_prog_dmaps_3, ex_prog_dmaps_3_data, ex_prog_dmaps_3_align_size = make_syspage_char(
            bytes([ex_id_ram]), addr, align, align_char
        )

        ex_align_size = (
            size_with_padding(SP_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_1_align_size
            + 3 * size_with_padding(MAP_ENTRY_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_2_align_size
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_map_name_3_align_size
            + size_with_padding(PROG_CORE_SIZE, align)
            + ex_prog_argv_1_align_size
            + ex_prog_imaps_1_align_size
            + ex_prog_dmaps_1_align_size
            + size_with_padding(PROG_CORE_SIZE, align)
            + ex_prog_argv_2_align_size
            + ex_prog_imaps_2_align_size
            + ex_prog_dmaps_2_align_size
            + size_with_padding(PROG_CORE_SIZE, align)
            + ex_prog_argv_3_align_size
            + ex_prog_imaps_3_align_size
            + ex_prog_dmaps_3_align_size
        )

        ex_attr_flash0 = 1 | 4
        ex_attr_flash1 = 1 | 4
        ex_attr_ram = 1 | 2 | 4

        ex_prog_start_1 = int(words["start1"], 0) + int(words["offs4"], 0)
        ex_prog_end_1 = ex_prog_start_1 + int(words["size4"], 0)
        ex_prog_imap_sz_1 = len(ex_prog_imaps_1.data)
        ex_prog_dmap_sz_1 = len(ex_prog_dmaps_1.data)

        ex_prog_start_2 = int(words["start1"], 0) + int(words["offs6"], 0)
        ex_prog_end_2 = ex_prog_start_2 + int(words["size6"], 0)
        ex_prog_imap_sz_2 = len(ex_prog_imaps_2.data)
        ex_prog_dmap_sz_2 = len(ex_prog_dmaps_2.data)

        ex_prog_start_3 = int(words["start1"], 0) + int(words["offs8"], 0)
        ex_prog_end_3 = ex_prog_start_3 + int(words["size8"], 0)
        ex_prog_imap_sz_3 = len(ex_prog_imaps_3.data)
        ex_prog_dmap_sz_3 = len(ex_prog_dmaps_3.data)

        ex_entry_type = SyspageMapEntStruct.EntryType.ALLOCATED

        # calculation of pointers
        ex_addr_map_1 = addr + size_with_padding(SP_CORE_SIZE, align)
        ex_addr_map_name_1 = ex_addr_map_1 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_entry_1_1 = ex_addr_map_name_1 + ex_map_name_1_align_size
        ex_addr_map_entry_1_2 = ex_addr_map_entry_1_1 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_entry_1_3 = ex_addr_map_entry_1_2 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_2 = ex_addr_map_entry_1_3 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_name_2 = ex_addr_map_2 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_3 = ex_addr_map_name_2 + ex_map_name_2_align_size
        ex_addr_map_name_3 = ex_addr_map_3 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_prog_1 = ex_addr_map_name_3 + ex_map_name_3_align_size
        ex_addr_prog_argv_1 = ex_addr_prog_1 + size_with_padding(PROG_CORE_SIZE, align)
        ex_addr_prog_imaps_1 = ex_addr_prog_argv_1 + ex_prog_argv_1_align_size
        ex_addr_prog_dmaps_1 = ex_addr_prog_imaps_1 + ex_prog_imaps_1_align_size
        ex_addr_prog_2 = ex_addr_prog_dmaps_1 + ex_prog_dmaps_1_align_size
        ex_addr_prog_argv_2 = ex_addr_prog_2 + size_with_padding(PROG_CORE_SIZE, align)
        ex_addr_prog_imaps_2 = ex_addr_prog_argv_2 + ex_prog_argv_2_align_size
        ex_addr_prog_dmaps_2 = ex_addr_prog_imaps_2 + ex_prog_imaps_2_align_size
        ex_addr_prog_3 = ex_addr_prog_dmaps_2 + ex_prog_dmaps_2_align_size
        ex_addr_prog_argv_3 = ex_addr_prog_3 + size_with_padding(PROG_CORE_SIZE, align)
        ex_addr_prog_imaps_3 = ex_addr_prog_argv_3 + ex_prog_argv_3_align_size
        ex_addr_prog_dmaps_3 = ex_addr_prog_imaps_3 + ex_prog_imaps_3_align_size

        # expected test data preparation
        ex_data = (
            syspage_hal_struct.pack()
            + pack_main(
                ex_align_size,
                0,
                ex_addr_map_1,
                ex_addr_prog_1,
                0,
            )
            + pack_map(
                ex_addr_map_2,
                ex_addr_map_3,
                ex_addr_map_entry_1_1,
                int(words["start1"], 0),
                int(words["end1"], 0),
                ex_attr_flash0,
                ex_id_flash0,
                ex_addr_map_name_1,
            )
            + ex_map_name_1_data
            + (
                pack_map_entry(
                    ex_addr_map_entry_1_2,
                    ex_addr_map_entry_1_3,
                    ex_entry_type,
                    ex_prog_start_1,
                    ex_prog_end_1,
                )
                + pack_map_entry(
                    ex_addr_map_entry_1_3,
                    ex_addr_map_entry_1_1,
                    ex_entry_type,
                    ex_prog_start_2,
                    ex_prog_end_2,
                )
                + pack_map_entry(
                    ex_addr_map_entry_1_1,
                    ex_addr_map_entry_1_2,
                    ex_entry_type,
                    ex_prog_start_3,
                    ex_prog_end_3,
                )
            )
            + pack_map(
                ex_addr_map_3,
                ex_addr_map_1,
                0,
                int(words["start2"], 0),
                int(words["end2"], 0),
                ex_attr_flash1,
                ex_id_flash1,
                ex_addr_map_name_2,
            )
            + ex_map_name_2_data
            + pack_map(
                ex_addr_map_1,
                ex_addr_map_2,
                0,
                int(words["start3"], 0),
                int(words["end3"], 0),
                ex_attr_ram,
                ex_id_ram,
                ex_addr_map_name_3,
            )
            + ex_map_name_3_data
            + pack_prog(
                ex_addr_prog_2,
                ex_addr_prog_3,
                ex_prog_start_1,
                ex_prog_end_1,
                ex_addr_prog_argv_1,
                ex_prog_imap_sz_1,
                ex_addr_prog_imaps_1,
                ex_prog_dmap_sz_1,
                ex_addr_prog_dmaps_1,
            )
            + ex_prog_argv_1_data
            + ex_prog_imaps_1_data
            + ex_prog_dmaps_1_data
            + pack_prog(
                ex_addr_prog_3,
                ex_addr_prog_1,
                ex_prog_start_2,
                ex_prog_end_2,
                ex_addr_prog_argv_2,
                ex_prog_imap_sz_2,
                ex_addr_prog_imaps_2,
                ex_prog_dmap_sz_2,
                ex_addr_prog_dmaps_2,
            )
            + ex_prog_argv_2_data
            + ex_prog_imaps_2_data
            + ex_prog_dmaps_2_data
            + pack_prog(
                ex_addr_prog_1,
                ex_addr_prog_2,
                ex_prog_start_3,
                ex_prog_end_3,
                ex_addr_prog_argv_3,
                ex_prog_imap_sz_3,
                ex_addr_prog_imaps_3,
                ex_prog_dmap_sz_3,
                ex_addr_prog_dmaps_3,
            )
            + ex_prog_argv_3_data
            + ex_prog_imaps_3_data
            + ex_prog_dmaps_3_data
        )

        # Act
        syspage._parse_content(cmds)
        actual_data = syspage.generate_syspage_img()

        # Assert
        self.assertEqual(actual_data, ex_data)


class TestCmdKernelimg(unittest.TestCase):
    def test_cmd_kernelimg(self):
        # Arrange
        addr = 0x100
        align = ALIGN
        align_char = ALIGN_CHAR
        syspage = Syspage(addr, addr + 0x200, align, align_char)
        syspage_hal_struct = SyspageHalStruct()
        cmds = (
            "map flash0 0x08000000 0x08080000 rx\n"
            "map ram 0x20000000 0x20050000 rwx\n"
            "alias phoenix-armv7m4-stm32l4x6.bin 0x7000 0xf400\n"
            "kernelimg flash0 phoenix-armv7m4-stm32l4x6.bin 8007000 f400 20000000 1200\n"
        )

        words = dict(
            zip(
                [
                    "cmd1",
                    "name1",
                    "start1",
                    "end1",
                    "attr1",
                    "cmd2",
                    "name2",
                    "start2",
                    "end2",
                    "attr2",
                    "cmd3",
                    "name3",
                    "offs3",
                    "size3",
                    "cmd4",
                    "dev4",
                    "name4",
                    "text_start4",
                    "text_size4",
                    "data_start4",
                    "data_size4",
                ],
                cmds.split(),
            )
        )

        ex_id_flash0 = 0
        ex_id_ram = 1

        _, ex_name_flash_data, ex_name_flash_align_size = make_syspage_char(
            make_c_string(words["name1"]), addr, align, align_char
        )
        _, ex_name_ram_data, ex_name_ram_align_size = make_syspage_char(
            make_c_string(words["name2"]), addr, align, align_char
        )

        ex_attr_flash0 = 1 | 4
        ex_attr_ram = 1 | 2 | 4

        ex_text_start = int(words["text_start4"], 16)
        ex_text_size = int(words["text_size4"], 16)
        ex_data_start = int(words["data_start4"], 16)
        ex_data_size = int(words["data_size4"], 16)

        ex_align_size = (
            size_with_padding(SP_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_name_flash_align_size
            + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
            + size_with_padding(MAP_CORE_SIZE, align)
            + ex_name_ram_align_size
            + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        )

        ex_entry_type = SyspageMapEntStruct.EntryType.ALLOCATED

        # calculation of pointers
        ex_addr_map_1 = addr + size_with_padding(SP_CORE_SIZE, align)
        ex_addr_map_name_1 = ex_addr_map_1 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_entry_1 = ex_addr_map_name_1 + ex_name_flash_align_size
        ex_addr_map_2 = ex_addr_map_entry_1 + size_with_padding(MAP_ENTRY_CORE_SIZE, align)
        ex_addr_map_name_2 = ex_addr_map_2 + size_with_padding(MAP_CORE_SIZE, align)
        ex_addr_map_entry_2 = ex_addr_map_name_2 + ex_name_ram_align_size

        # expected test data preparation
        ex_data = (
            syspage_hal_struct.pack()
            + pack_main(
                ex_align_size,
                ex_text_start,
                ex_addr_map_1,
                0,
                0,
            )
            + pack_map(
                ex_addr_map_2,
                ex_addr_map_2,
                ex_addr_map_entry_1,
                int(words["start1"], 0),
                int(words["end1"], 0),
                ex_attr_flash0,
                ex_id_flash0,
                ex_addr_map_name_1,
            )
            + ex_name_flash_data
            + pack_map_entry(
                ex_addr_map_entry_1,
                ex_addr_map_entry_1,
                ex_entry_type,
                ex_text_start,
                ex_text_start + ex_text_size,
            )
            + pack_map(
                ex_addr_map_1,
                ex_addr_map_1,
                ex_addr_map_entry_2,
                int(words["start2"], 0),
                int(words["end2"], 0),
                ex_attr_ram,
                ex_id_ram,
                ex_addr_map_name_2,
            )
            + ex_name_ram_data
            + pack_map_entry(
                ex_addr_map_entry_2,
                ex_addr_map_entry_2,
                ex_entry_type,
                ex_data_start,
                ex_data_start + ex_data_size,
            )
        )

        # Act
        syspage._parse_content(cmds)
        actual_data = syspage.generate_syspage_img()

        # Assert
        self.assertEqual(actual_data, ex_data)


if __name__ == "__main__":
    unittest.main()
