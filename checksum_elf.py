#
# Build system
#
# Utility to add CRC32 checksum to ELF files if a PT_NOTE with 0x70727400 magic
# is found.
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import sys
import struct
import zlib
from elftools.elf.elffile import ELFFile


def patch_note_elf(filepath):
    with open(filepath, "r+b") as f:
        file_bytes = bytearray(f.read())
        f.seek(0)
        elf = ELFFile(f)

        checksum_file_offset = None
        endian = "<" if elf.little_endian else ">"

        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_NOTE":
                seg_offset = segment["p_offset"]
                seg_size = segment["p_filesz"]
                align = segment["p_align"] if segment["p_align"] > 1 else 4

                offset = seg_offset
                end_offset = seg_offset + seg_size
                while offset + 12 <= end_offset:
                    if offset + 12 > len(file_bytes):
                        break
                    namesz, descsz, note_type = struct.unpack(
                        endian + "III", file_bytes[offset : offset + 12]
                    )
                    namesz_padded = ((namesz + align - 1) // align) * align
                    descsz_padded = ((descsz + align - 1) // align) * align

                    if note_type == 0x70727400:
                        checksum_file_offset = offset + 12 + namesz_padded
                        break

                    offset += 12 + namesz_padded + descsz_padded

                if checksum_file_offset is not None:
                    break

        if checksum_file_offset is None or checksum_file_offset + 4 > len(file_bytes):
            sys.exit(0)

        file_bytes[checksum_file_offset : checksum_file_offset + 4] = (
            b"\x00\x00\x00\x00"
        )

        payload = bytearray()
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                p_off = segment["p_offset"]
                p_sz = segment["p_filesz"]
                payload.extend(file_bytes[p_off : p_off + p_sz])

        crc = zlib.crc32(payload) & 0xFFFFFFFF

        f.seek(checksum_file_offset)
        f.write(struct.pack(endian + "I", crc))
        print(
            f"[{filepath}] PT_NOTE CRC32 patched: 0x{crc:08X} at offset 0x{checksum_file_offset:X}"
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <elf_file>", file=sys.stderr)
        sys.exit(1)
    patch_note_elf(sys.argv[1])
