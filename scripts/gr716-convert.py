#!/usr/bin/env python3
#
# Script to convert ELF file to ASW format for GR716
#
# Copyright 2023 Phoenix Systems
# Author: Lukasz Leczkowski
#

import argparse
import os


READELF = "sparc-phoenix-readelf"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert ELF file to ASW format for GR716"
    )
    parser.add_argument("filename", help="ELF file to convert")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("-e", "--entrypoint", help="entry point address (hex)")
    return parser.parse_args()


def validate_file(filename: str):
    if not os.path.isfile(filename):
        print(f'Error: file "{filename}" not found')
        exit(1)


def read_phdrs(filename: str):
    # Get offset and size of LOAD program headers
    phdrs = os.popen(f"{READELF} -l {filename} | grep LOAD").read()

    # PLO has only one LOAD program header
    # Get offset and size of LOAD program headers
    phdrs = phdrs.split()
    phdrs.remove("LOAD")

    offset = int(phdrs[0], 16)
    filesize = int(phdrs[3], 16)

    return offset, filesize


def crc_encode(data: bytearray):
    """16-bit CRC according to ECSS-E-70-41A"""

    def crc(byte: int, chk: int):
        for i in range(8):
            if (byte & 0x80) ^ ((chk & 0x8000) >> 8):
                chk = ((chk << 1) ^ 0x1021) & 0xFFFF
            else:
                chk = (chk << 1) & 0xFFFF
            byte = byte << 1
        return chk

    chk = 0xFFFF
    for val in data:
        chk = crc(val, chk)

    return chk


def convert_file(inputfn: str, outputfn: str, entry: int):
    offset, filesize = read_phdrs(inputfn)

    with open(args.filename, "rb") as inputfile, open(outputfn, "w+b") as outputfile:
        inputfile.seek(offset)
        data = inputfile.read(filesize)

        # Define image header:
        #   user defined id
        #   entry point
        #   image section headers
        #   image header checksum

        # workaround for early GR716 revision
        # if we skip bootloader, this will be the first executed instruction
        # that will jump to the entry point
        usr_id = 0x3080002b

        outputfile.write(usr_id.to_bytes(4, "big"))
        outputfile.write(entry.to_bytes(4, "big"))

        # entry point magic - undocumented errata - instead of section 0
        magic = (
            (0x0).to_bytes(4, "big")
            + "EP->".encode("ascii")
            + entry.to_bytes(4, "big")
            + " GR716 \0".encode("ascii")
        )
        outputfile.write(magic)

        # Define image section header:
        #   flags: 0x1 - copy to RAM
        #   relative offset to data: 0x2B (in 32-bit words)
        #   absolute destination address: entry point
        #   length of image (in 32-bit words)
        #   checksum of image data

        outputfile.write((0x1).to_bytes(4, "big"))
        outputfile.write((0x2B).to_bytes(4, "big"))
        outputfile.write(entry.to_bytes(4, "big"))
        outputfile.write((filesize // 4).to_bytes(4, "big"))

        data_chk = crc_encode(bytearray(data))
        outputfile.write(data_chk.to_bytes(2, "big"))
        outputfile.write(b"\x00\x00")

        # write 6 clear sections (unused)
        for i in range(6):
            for j in range(5):
                outputfile.write((0x0).to_bytes(4, "big"))

        outputfile.write(b"\x00\x00")  # padding

        hdr_chk_pos = outputfile.tell()
        outputfile.seek(0, 0)

        # calculate checksum over image section header
        hdrs = bytearray(outputfile.read())
        hdr_chk = crc_encode(hdrs)
        outputfile.seek(hdr_chk_pos, 0)
        outputfile.write(hdr_chk.to_bytes(2, "big"))

        outputfile.write(data)

    print(f"Converted {inputfn} to {outputfn}")


if __name__ == "__main__":
    args = parse_args()
    try:
        entry = int(args.entrypoint, 16) if args.entrypoint else 0x31000000
    except ValueError as e:
        print(f"Error: {args.entrypoint} is not a valid entry point address")
        exit(1)

    validate_file(args.filename)
    outputfn = args.output if args.output else args.filename.replace(".elf", ".asw")
    convert_file(args.filename, outputfn, entry)
