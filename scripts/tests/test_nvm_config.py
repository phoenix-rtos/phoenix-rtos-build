#
# nvm_config.py tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from nvm_config import PartitionType, find_target_part, read_nvm


def nvm(tree, text):
    return read_nvm(tree.write("nvm.yaml", text))


def layout(flash):
    return [(p.name, p.offs, p.size) for p in flash.parts]


def test_offsets_and_last_size_inferred(tree):
    [flash] = nvm(tree, """
        flash0:
          size: 0x100000
          block_size: 0x1000
          partitions:
            - {name: plo, size: 0x10000}
            - {name: kernel, size: 0x20000}
            - {name: rootfs, type: jffs2}
        """)

    assert (flash.name, flash.size, flash.block_size, flash.padding_byte) == ("flash0", 0x100000, 0x1000, 0)
    assert layout(flash) == [("plo", 0, 0x10000), ("kernel", 0x10000, 0x20000), ("rootfs", 0x30000, 0xd0000)]
    assert [p.type for p in flash.parts] == [PartitionType.RAW, PartitionType.RAW, PartitionType.JFFS2]
    assert all(p.flash is flash for p in flash.parts)


def test_size_inferred_from_next_offset(tree):
    [flash] = nvm(tree, """
        flash0:
          size: 0x100000
          block_size: 0x1000
          padding_byte: 0xff
          partitions:
            - {name: plo}
            - {name: kernel, offs: 0x20000}
            - {name: rootfs, offs: 0x80000, size: 0x40000}
        """)

    assert flash.padding_byte == 0xff
    assert layout(flash) == [("plo", 0, 0x20000), ("kernel", 0x20000, 0x60000), ("rootfs", 0x80000, 0x40000)]


def test_virtual_partitions(tree):
    [flash] = nvm(tree, """
        hd0:
          size: 0x100000
          block_size: 0x1000
          partitions:
            - {name: mbr, offs: 0x1be, size: 0x10, virtual: True}
            - {name: plo, size: 0x10000}
            - {name: rootfs, empty: True}
        """)

    mbr, plo, rootfs = flash.parts
    assert (mbr.virtual, mbr.filename) == (True, "part_hd0_mbr.img")
    assert (plo.offs, plo.filename) == (0, "part_plo.img")  # virtual partition doesn't move the offset
    assert (rootfs.empty, rootfs.size) == (True, 0xf0000)
    assert flash.ptable_filename == "hd0.ptable"


def test_ptable_blocks(tree):
    [flash] = nvm(tree, """
        flash0:
          size: 0x100000
          block_size: 0x10000
          ptable_blocks: 2
          partitions:
            - {name: kernel, size: 0x40000}
            - {name: rootfs, size: 0x40000}
        """)

    ptable = flash.parts[-1]
    assert (ptable.name, ptable.offs, ptable.size, ptable.virtual) == ("ptable", 0xe0000, 0x20000, True)
    assert ptable.filename == "part_flash0_ptable.img"


def test_ptable_blocks_not_overlapped(tree):
    [flash] = nvm(tree, """
        flash0:
          size: 0x100000
          block_size: 0x10000
          ptable_blocks: 1
          partitions:
            - {name: kernel, size: 0x40000}
            - {name: rootfs}
        """)

    rootfs, ptable = flash.parts[-2:]
    assert rootfs.offs + rootfs.size == ptable.offs


def test_ptable_blocks_overlap_error(tree):
    with pytest.raises(ValueError, match="'rootfs' overlaps the ptable blocks"):
        nvm(tree, """
            flash0:
              size: 0x100000
              block_size: 0x10000
              ptable_blocks: 1
              partitions:
                - {name: kernel, size: 0x40000}
                - {name: rootfs, size: 0xc0000}
            """)


@pytest.mark.parametrize("value, expected", [
    ("raw", PartitionType.RAW), ("JFFS2", PartitionType.JFFS2),
    ("meterfs", PartitionType.METERFS), ("futurefs", PartitionType.FUTUREFS),
    (0x72, PartitionType.JFFS2),
])
def test_partition_types(tree, value, expected):
    [flash] = nvm(tree, f"""
        flash0:
          size: 0x10000
          block_size: 0x1000
          partitions:
            - {{name: data, type: {value}}}
        """)

    assert flash.parts[0].type == expected


def test_partition_type_invalid(tree):
    with pytest.raises(ValueError, match="not a valid PartitionType"):
        nvm(tree, """
            flash0:
              size: 0x10000
              block_size: 0x1000
              partitions:
                - {name: data, type: ext4}
            """)


@pytest.mark.parametrize("parts, error", [
    ("[{name: a, size: 0x1000}, {name: a}]", "duplicate partition name 'a'"),
    ("[{name: a, offs: 0x800}]", "start 0x800 is not aligned"),
    ("[{name: a, size: 0x1800}]", "size 0x1800 is not aligned"),
    ("[{name: a, offs: 0x4000, size: 0x1000}, {name: b, offs: 0x2000, size: 0x1000}]", "not monotonic"),
    ("[{name: a, size: 0x4000}, {name: b, offs: 0x2000, size: 0x1000}]", "'b' and 'a' are overlapping"),
    ("[{name: a, size: 0x20000}]", "'a' size extends over the end of the flash"),
])
def test_validation_errors(tree, parts, error):
    with pytest.raises(ValueError, match=error):
        nvm(tree, f"""
            flash0:
              size: 0x10000
              block_size: 0x1000
              partitions: {parts}
            """)


def test_find_target_part(tree):
    flashes = nvm(tree, """
        flash0:
          size: 0x10000
          block_size: 0x1000
          partitions:
            - {name: kernel, size: 0x4000}
            - {name: rootfs}
        flash1:
          size: 0x10000
          block_size: 0x1000
          partitions:
            - {name: rootfs}
        """)

    assert [f.name for f in flashes] == ["flash0", "flash1"]
    assert find_target_part(flashes, "rootfs") is flashes[0].parts[1]  # first match
    assert find_target_part(flashes, "flash1:rootfs") is flashes[1].parts[0]
    assert find_target_part(flashes, "flash1:kernel") is None
    assert find_target_part(flashes, "missing") is None


def test_str(tree):
    [flash] = nvm(tree, """
        flash0:
          size: 0x200000
          block_size: 0x1000
          partitions:
            - {name: mtd, size: 0x1000, virtual: True}
            - {name: rootfs, type: jffs2}
        """)

    text = str(flash)
    assert text.startswith("FlashMemory(flash0)  size=0x200000 [2 MB] block_size=0x1000")
    assert "E 0x000000  0x001000  [    4 kB]   mtd          raw" in text
    assert "  0x000000  0x200000  [ 2048 kB]   rootfs       jffs2" in text
