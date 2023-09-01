#!/usr/bin/env python3
#
# Generate BCH EDAC for GR716
#
# Copyright 2023 Phoenix Systems
# Author: Lukasz Leczkowski
#

import argparse
import os


BOLD = "\033[1m"
NORMAL = "\033[0m"
GREEN = "\033[32m"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate BCH EDAC for GR716"
    )
    parser.add_argument("input", help="file to convert")
    parser.add_argument("output", help="output file")
    parser.add_argument("-s", "--size", help="size of the flash memory (default 16 MiB)")
    return parser.parse_args()


def validate_file(filename: str):
    if not os.path.isfile(filename):
        print(f'Error: file "{filename}" not found')
        exit(1)


def checksum(word: int):
    """ GR716 manual section 21.4 """
    w = [(word >> i) & 1 for i in range(32)]
    cb = [
        w[0] ^ w[4] ^ w[6] ^ w[7] ^ w[8] ^ w[9] ^ w[11] ^ w[14] ^ w[17] ^ w[18] ^ w[19] ^ w[21] ^ w[26] ^ w[28] ^ w[29] ^ w[31],
        w[0] ^ w[1] ^ w[2] ^ w[4] ^ w[6] ^ w[8] ^ w[10] ^ w[12] ^ w[16] ^ w[17] ^ w[18] ^ w[20] ^ w[22] ^ w[24] ^ w[26] ^ w[28],
        (w[0] ^ w[3] ^ w[4] ^ w[7] ^ w[9] ^ w[10] ^ w[13] ^ w[15] ^ w[16] ^ w[19] ^ w[20] ^ w[23] ^ w[25] ^ w[26] ^ w[29] ^ w[31]) ^ 1,
        (w[0] ^ w[1] ^ w[5] ^ w[6] ^ w[7] ^ w[11] ^ w[12] ^ w[13] ^ w[16] ^ w[17] ^ w[21] ^ w[22] ^ w[23] ^ w[27] ^ w[28] ^ w[29]) ^ 1,
        w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^ w[14] ^ w[15] ^ w[18] ^ w[19] ^ w[20] ^ w[21] ^ w[22] ^ w[23] ^ w[30] ^ w[31],
        w[8] ^ w[9] ^ w[10] ^ w[11] ^ w[12] ^ w[13] ^ w[14] ^ w[15] ^ w[24] ^ w[25] ^ w[26] ^ w[27] ^ w[28] ^ w[29] ^ w[30] ^ w[31],
        w[0] ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^ w[24] ^ w[25] ^ w[26] ^ w[27] ^ w[28] ^ w[29] ^ w[30] ^ w[31]
    ]
    res = 0
    for i in range(7):
        res |= cb[i] << i

    return res


def generate_bch(data: bytearray):
    edac = bytearray()
    for word in range(0, len(data), 4):
        edac.insert(0, checksum(int.from_bytes(data[word:word+4], byteorder='big')))

    return edac


def main():
    args = parse_args()
    try:
        size = int(args.size) if args.size else 16 * 1024 * 1024
    except:
        print(f'Error: invalid size "{args.size}"')
        exit(1)

    validate_file(args.input)

    with open(args.input, 'rb') as f:
        data = f.read()

    while len(data) % (16 * 4) != 0:
        data += b'\x50\x41\x44\x21' # PAD!

    with open(args.input, 'wb') as f:
        f.write(data)

    bch = generate_bch(bytearray(data))

    with open(args.output, 'wb') as f:
        f.write(bch)

    print(f"Generated BCH of {args.input} to {args.output}")
    print(f"{BOLD}{GREEN}Please load the BCH file to the SPI flash at offset {hex(size - len(bch))}{NORMAL}")


if __name__ == "__main__":
    main()
