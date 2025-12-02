#!/usr/bin/env python3

# Phoenix-RTOS
#
# Unit tests for hal_armv7m_stm32_l4.py
#
# Copyright 2025 Phoenix Systems
# Author: Damian Jozwiak
#
# %LICENSE%

import unittest
import struct
from hal_armv7m_stm32_l4 import Attr, SyspageHalStruct

HAL_FMT = "<II" + "II" * 16 + "I" * 16
HAL_CORE_SIZE = struct.calcsize(HAL_FMT)


class TestSyspageHalRegisters(unittest.TestCase):
    def test_mpu_flash0(self):
        # Arrange
        start_addr = 0x08000000
        end_addr = 0x08080000
        attr = Attr.READ | Attr.EXEC
        region_id = 0
        enable = 1

        ex_rbar = 0x08000010
        ex_rasr = 0x0200FE2B

        shs = SyspageHalStruct()

        # Act
        shs.alloc_mpu_region(start_addr, end_addr, attr, region_id, enable)
        actual_rbar = shs._mpu_table[0].rbar
        actual_rasr = shs._mpu_table[0].rasr
        actual_region_id = shs._mpu_map[0]
        # Assert
        self.assertEqual(actual_rbar, ex_rbar)
        self.assertEqual(actual_rasr, ex_rasr)
        self.assertEqual(actual_region_id, region_id)

    def test_mpu_flash1(self):
        # Arrange
        start_addr = 0x08080000
        end_addr = 0x08100000
        attr = Attr.READ | Attr.EXEC
        region_id = 1
        enable = 1

        ex_rbar = 0x08000010  # 0x08000011
        ex_rasr = 0x0200FD2B

        shs = SyspageHalStruct()

        # Act
        shs.alloc_mpu_region(start_addr, end_addr, attr, region_id, enable)
        actual_rbar = shs._mpu_table[0].rbar
        actual_rasr = shs._mpu_table[0].rasr
        actual_region_id = shs._mpu_map[0]
        # Assert
        self.assertEqual(actual_rbar, ex_rbar)
        self.assertEqual(actual_rasr, ex_rasr)
        self.assertEqual(actual_region_id, region_id)

    def test_mpu_ram(self):
        # Arrange
        start_addr = 0x20000000
        end_addr = 0x20050000
        attr = Attr.READ | Attr.WRITE | Attr.EXEC
        region_id = 2
        enable = 1

        ex_rbar = 0x20000010  # 0x20000012
        ex_rasr = 0x0300E025

        shs = SyspageHalStruct()

        # Act
        shs.alloc_mpu_region(start_addr, end_addr, attr, region_id, enable)
        actual_rbar = shs._mpu_table[0].rbar
        actual_rasr = shs._mpu_table[0].rasr
        actual_region_id = shs._mpu_map[0]
        # Assert
        self.assertEqual(actual_rbar, ex_rbar)
        self.assertEqual(actual_rasr, ex_rasr)
        self.assertEqual(actual_region_id, region_id)


class TestSyspageHal(unittest.TestCase):
    def test_SyspageHalStruct_default_empty(self):
        # Arrange
        ex_core_size = HAL_CORE_SIZE
        ex_mpu_type = 0x00000800
        # See hal_syspage_t for stm32 armv7m
        ex_data = ex_mpu_type.to_bytes(4, byteorder="little") + b"\x00" * (1 * 4 + (2 * 4) * 16) + b"\xff" * (4 * 16)
        syspage_hal_struct = SyspageHalStruct()
        # Act
        actual_core_size = syspage_hal_struct.core_size()
        actual_data = syspage_hal_struct.pack()

        # Assert
        self.assertEqual(actual_core_size, ex_core_size)
        self.assertEqual(actual_data, ex_data)

    def test_SyspageHalStruct(self):
        # Arrange
        ex_core_size = HAL_CORE_SIZE
        ex_mpu_type = 0x00000800
        ex_mpu_alloc_cnt = 0x00000000
        mpu_table_rbar_1 = 0x00000003
        mpu_table_rasr_1 = 0x00000004
        mpu_table_rbar_2 = 0x00000005
        mpu_table_rasr_2 = 0x00000006
        mpu_map_1 = 0x00000007
        mpu_map_2 = 0x00000008

        syspage_hal_struct = SyspageHalStruct()
        syspage_hal_struct._mpu_table[0].rbar = mpu_table_rbar_1
        syspage_hal_struct._mpu_table[0].rasr = mpu_table_rasr_1
        syspage_hal_struct._mpu_table[1].rbar = mpu_table_rbar_2
        syspage_hal_struct._mpu_table[1].rasr = mpu_table_rasr_2
        syspage_hal_struct._mpu_map[0] = mpu_map_1
        syspage_hal_struct._mpu_map[1] = mpu_map_2

        ex_data = (
            ex_mpu_type.to_bytes(4, byteorder="little")
            + ex_mpu_alloc_cnt.to_bytes(4, byteorder="little")
            + mpu_table_rbar_1.to_bytes(4, byteorder="little")
            + mpu_table_rasr_1.to_bytes(4, byteorder="little")
            + mpu_table_rbar_2.to_bytes(4, byteorder="little")
            + mpu_table_rasr_2.to_bytes(4, byteorder="little")
            + b"\x00" * (14 * (2 * 4))
            + mpu_map_1.to_bytes(4, byteorder="little")
            + mpu_map_2.to_bytes(4, byteorder="little")
            + b"\xff" * (14 * 4)
        )

        # Act
        actual_core_size = syspage_hal_struct.core_size()
        actual_data = syspage_hal_struct.pack()

        # Assert
        self.assertEqual(actual_core_size, ex_core_size)
        self.assertEqual(actual_data, ex_data)

    def test_SyspageHalStruct_invalidate(self):
        # Arrange
        ex_core_size = HAL_CORE_SIZE
        ex_mpu_type = 0x00000800
        ex_mpu_alloc_cnt = 0x00000000

        mpu_table_rasr = 0x1000003E
        mpu_map = 0xFFFFFFFF

        syspage_hal_struct = SyspageHalStruct()
        syspage_hal_struct.invalidate()

        ex_data = ex_mpu_type.to_bytes(4, byteorder="little") + ex_mpu_alloc_cnt.to_bytes(4, byteorder="little")
        for i in range(8):
            ex_data = ex_data + i.to_bytes(4, byteorder="little") + mpu_table_rasr.to_bytes(4, byteorder="little")

        ex_data = ex_data + 8 * 2 * 4 * b"\x00"
        ex_data = ex_data + 16 * mpu_map.to_bytes(4, byteorder="little")

        # Act
        actual_core_size = syspage_hal_struct.core_size()
        actual_data = syspage_hal_struct.pack()

        # Assert
        self.assertEqual(actual_core_size, ex_core_size)
        self.assertEqual(actual_data, ex_data)

    def test_SyspageHalStruct_with_maps(self):
        # Arrange
        start_addr_flash0 = 0x08000000
        end_addr_flash0 = 0x08080000
        attr_flash0 = Attr.READ | Attr.EXEC
        map_id_flash0 = 0

        start_addr_flash1 = 0x08080000
        end_addr_flash1 = 0x08100000
        attr_flash1 = Attr.READ | Attr.EXEC
        map_id_flash1 = 1

        start_addr_ram = 0x20000000
        end_addr_ram = 0x20050000
        attr_ram = Attr.READ | Attr.WRITE | Attr.EXEC
        map_id_ram = 2

        enable = 1

        ex_mpu_type = 0x00000800
        ex_mpu_alloc_cnt = 0x0000003

        ex_rbar_flash0 = 0x08000010
        ex_rasr_flash0 = 0x0200FE2B
        ex_rbar_flash1 = 0x08000011
        ex_rasr_flash1 = 0x0200FD2B
        ex_rbar_ram = 0x20000012
        ex_rasr_ram = 0x0300E025

        ex_rasr_invalidate = 0x1000003E
        ex_map_invalidate = 0xFFFFFFFF

        ex_data = struct.pack("<II", ex_mpu_type, ex_mpu_alloc_cnt)
        ex_data += struct.pack("<II", ex_rbar_flash0, ex_rasr_flash0)
        ex_data += struct.pack("<II", ex_rbar_flash1, ex_rasr_flash1)
        ex_data += struct.pack("<II", ex_rbar_ram, ex_rasr_ram)
        for i in range(3, 8):
            ex_data += struct.pack("<II", i, ex_rasr_invalidate)
        ex_data += 8 * struct.pack("<II", 0, 0)
        ex_data += struct.pack("<III", map_id_flash0, map_id_flash1, map_id_ram)
        for i in range(8 - 3 + 8):
            ex_data += struct.pack("<I", ex_map_invalidate)

        ex_size = HAL_CORE_SIZE

        # Act
        shs = SyspageHalStruct()
        shs.invalidate()
        shs.alloc_mpu_region(start_addr_flash0, end_addr_flash0, attr_flash0, map_id_flash0, enable)
        shs.alloc_mpu_region(start_addr_flash1, end_addr_flash1, attr_flash1, map_id_flash1, enable)
        shs.alloc_mpu_region(start_addr_ram, end_addr_ram, attr_ram, map_id_ram, enable)
        actual_core_size = shs.core_size()
        actual_data = shs.pack()

        # Assert
        self.assertEqual(actual_core_size, ex_size)
        self.assertEqual(actual_data, ex_data)
