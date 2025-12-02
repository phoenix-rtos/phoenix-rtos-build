#!/usr/bin/env python3

# Phoenix-RTOS
#
# Script to generate syspage HAL part for stm32 armv7m4 L4
#
# Copyright 2025 Phoenix Systems
# Author: Damian Jozwiak
#
# %LICENSE%

from enum import IntEnum
from dataclasses import dataclass, field
import struct


# No need attr translation from map attr (the same value)
class Attr(IntEnum):
    READ = 0x01
    WRITE = 0x02
    EXEC = 0x04
    SHAREABLE = 0x08
    CACHEABLE = 0x10
    BUFFERABLE = 0x20


UINT_T = "I"


# List of linker symbols needed to build syspage (retrieved from *.elf)
LINKER_SYMBOLS = [
    "__init_start",
    "__init_end",
    "__text_start",
    "__etext",
    "__rodata_start",
    "__rodata_end",
    "__init_array_start",
    "__init_array_end",
    "__fini_array_start",
    "__fini_array_end",
    "__ramtext_start",
    "__ramtext_end",
    "__data_start",
    "__data_end",
    "__bss_start",
    "__bss_end",
    "__heap_base",
    "__heap_limit",
    "__stack_limit",
    "__stack_top",
]


def hal_get_memory_areas(ld_symbols: dict[str, int]) -> list[tuple[int, int]]:
    hal_memory_area = [
        (ld_symbols["__init_start"], ld_symbols["__init_end"]),
        (ld_symbols["__text_start"], ld_symbols["__etext"]),
        (ld_symbols["__rodata_start"], ld_symbols["__rodata_end"]),
        (ld_symbols["__init_array_start"], ld_symbols["__init_array_end"]),
        (ld_symbols["__fini_array_start"], ld_symbols["__fini_array_end"]),
        (ld_symbols["__ramtext_start"], ld_symbols["__ramtext_end"]),
        (ld_symbols["__data_start"], ld_symbols["__data_end"]),
        (ld_symbols["__bss_start"], ld_symbols["__bss_end"]),
        (ld_symbols["__heap_base"], ld_symbols["__heap_limit"]),
        (ld_symbols["__stack_limit"], ld_symbols["__stack_top"]),
    ]
    return hal_memory_area


@dataclass
class SyspageHalStruct:
    @dataclass
    class TableMpu:
        rbar: int = 0
        rasr: int = 0

        def pack(self) -> bytes:
            return struct.pack("<" + UINT_T + UINT_T, self.rbar, self.rasr)

        @classmethod
        def core_size(cls) -> int:
            return struct.calcsize("<" + UINT_T + UINT_T)

    _mpu_type: int = 0x00000800
    _mpu_alloc_cnt: int = 0
    _mpu_alloc_max: int = 8
    _mpu_table: list[TableMpu] | None = field(default=None)
    _mpu_map: list[int] | None = field(default=None)

    def __post_init__(self):
        if self._mpu_table is None:
            self._mpu_table = [SyspageHalStruct.TableMpu() for _ in range(16)]
        elif len(self._mpu_table) != 16:
            raise ValueError("MPU table size must be 16")
        if self._mpu_map is None:
            self._mpu_map = [0xFFFFFFFF] * 16
        elif len(self._mpu_map) != 16:
            raise ValueError("MPU map size must be 16")

    def invalidate(self) -> None:
        for region in range(self._mpu_alloc_max):
            self._mpu_table[region].rbar = self.mpu_make_rbar(0, 0, region, False)
            self._mpu_table[region].rasr = self.mpu_make_rasr(0, True, 0, False, False, False, 0, 0x0000001F, False)

    def mpu_make_rbar(self, base_addr: int, region_size: int, region_id: int, valid: bool) -> int:
        """MPU region base address register"""

        # Align base address to region size.
        # Lowest N bits must be zero, where N = log2(region size from  MPU_RASR).
        # For 4GB region size, addr should be 0x00000000.
        addr = base_addr & ~(region_size - 1)
        valid_bit = valid << 4
        rbar = (addr & 0xFFFFFFE0) | (region_id & 0xF) | valid_bit
        return rbar

    def mpu_make_rasr(
        self,
        ap: int = 3,
        xn: bool = 0,
        tex: int = 0,
        s: bool = 0,
        c: bool = 1,
        b: bool = 1,
        srd_mask: int = 0,
        region_size: int = 0,
        enable: bool = 1,
    ) -> int:
        rasr = sum(
            [
                xn << 28,
                (ap & 0x7) << 24,
                (tex & 0x7) << 19,
                s << 18,
                c << 17,
                b << 16,
                (srd_mask & 0xFF) << 8,
                (region_size & 0x1F) << 1,
                enable,
            ]
        )
        return rasr

    def _ctz(self, x: int) -> int:
        """Count trailing zeros"""
        if x == 0:
            return 32  # max value
        return (x & -x).bit_length() - 1

    def mpu_region_best_fit(self, start: int, end: int):
        size = end - start
        assert size > 0

        # The largest power of two by which the address / size is divisible
        addr_align_bits = self._ctz(start)
        size_align_bits = self._ctz(size)
        # The subregion must be aligned to both the address and the region size.
        subregion_align_bits = min(addr_align_bits, size_align_bits)

        # MPU does not support regions < 32B
        # MPU does not support subregions for regions smaller than 128
        if subregion_align_bits < 5:
            region_align_bits = 5
            region_size = 1 << region_align_bits
            region_base = start & (~(region_size - 1))
            rasr_size = region_align_bits - 1  # (Region size in bytes) = 2^(RASR.SIZE+1)
            rasr_srd = 0x00
            return rasr_size, rasr_srd, region_base, region_size

        # region = 8 * subregion; each region has 8 subregions
        # additionally, the problem with regions smaller than 128 has been solved
        region_align_bits = subregion_align_bits + 3

        # The maximum region size is 4GB.
        if region_align_bits >= 32:
            region_align_bits = 32
            region_align_mask = 0x00000000
        else:
            region_align_mask = (0xFFFFFFFF << region_align_bits) & 0xFFFFFFFF

        region_base = start & region_align_mask
        subregion_size = 1 << subregion_align_bits

        # Build subregion mask (1 = disabled)
        rasr_srd = 0
        alloc_size = 0
        subregion_base = region_base

        for i in range(8):
            # Subregion range:
            subregion_start = subregion_base
            subregion_end = subregion_base + subregion_size

            # Disable when:
            # - subregion starts befor start
            # - subregion ends after end
            # - using it would exceed the requested area
            # if subregion_end <= start or subregion_start >= end:
            if subregion_start < start or subregion_end > end or alloc_size + subregion_size > end - start:
                rasr_srd |= 1 << i
            else:
                alloc_size += subregion_size

            subregion_base += subregion_size

        # (Region size in bytes) = 2^(RASR.SIZE+1)
        rasr_size = region_align_bits - 1

        return rasr_size, rasr_srd, region_base, alloc_size

    def _prepare_rbar_args(self, attr: int, enable: bool):
        ap = 1
        if attr & Attr.READ:
            ap = 2
        if attr & Attr.WRITE:
            ap = 3
        xn = False if (attr & Attr.EXEC) else True
        tex = 0
        s = True if (attr & Attr.SHAREABLE) else False
        c = True if (attr & Attr.CACHEABLE) else False
        b = True if (attr & Attr.BUFFERABLE) else False

        return {"ap": ap, "xn": xn, "tex": tex, "s": s, "c": c, "b": b, "enable": enable}

    def alloc_mpu_region(self, start: int, end: int, attr: int, region_id: int, enable: int) -> None:
        size = end - start
        # A maximum of two regions per map
        for _ in range(2):
            if self._mpu_alloc_cnt + 1 >= self._mpu_alloc_max:
                raise RuntimeError("No free MPU regions available")

            region_size, srd_mask, region_base, alloc_size = self.mpu_region_best_fit(start, end)

            if alloc_size > size:
                raise RuntimeError(f"Allocated region exceeds requested size({alloc_size}B instead {size}B)")

            self._mpu_table[self._mpu_alloc_cnt].rbar = self.mpu_make_rbar(
                region_base, region_size, self._mpu_alloc_cnt, True
            )
            self._mpu_table[self._mpu_alloc_cnt].rasr = self.mpu_make_rasr(
                **self._prepare_rbar_args(attr, enable), srd_mask=srd_mask, region_size=region_size
            )
            self._mpu_map[self._mpu_alloc_cnt] = region_id
            self._mpu_alloc_cnt += 1

            if alloc_size == size:
                break

            start += alloc_size
            size -= alloc_size
        else:
            raise RuntimeError(f"Requested region could not be fully allocated ({size}B not allocated)")

    def pack(self) -> bytes:
        data = struct.pack("<" + UINT_T + UINT_T, self._mpu_type, self._mpu_alloc_cnt)
        for entry in self._mpu_table:
            data += entry.pack()
        data += struct.pack("<" + UINT_T * len(self._mpu_map), *self._mpu_map)
        assert self.core_size() == len(data)
        return data

    @classmethod
    def core_size(cls) -> int:
        return (
            struct.calcsize("<" + UINT_T + UINT_T) + 16 * cls.TableMpu.core_size() + struct.calcsize("<" + 16 * UINT_T)
        )
