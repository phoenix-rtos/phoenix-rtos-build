#!/usr/bin/env python3
#
# Sign elf files
#
# Copyright 2026 Phoenix Systems
# Author: Krzysztof Radzewicz
#
# SPDX-License-Identifier: BSD-3-Clause

from typing import BinaryIO
from pathlib import Path
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import ECC
import argparse
from tempfile import TemporaryFile

from strip import *
from image_builder import HashAlgorithm, read_pem_priv_key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sign an ELF file (ECC only)")
    parser.add_argument("-i", "--input", type=Path, required=True, help="Path to input ELF file")
    parser.add_argument("--private-key", type=Path, required=True, help="Path to private ECC key")
    parser.add_argument("--passwd", type=str, required=True, help="Password for encrypted private key")
    parser.add_argument("--hash", type=HashAlgorithm, default=HashAlgorithm.SHA2_256, choices=list(HashAlgorithm), help="Hashing algorithm")
    parser.add_argument("-o", "--output", type=Path, required=False, help="Path to output file (modify in place by default)")

    args = parser.parse_args()
    if args.output is None:
        args.output = args.input
    
    return args


def sign_elf_file(input: BinaryIO, key_path: Path, passwd: bytes, hash_algo: HashAlgorithm):
    parser = ElfParser(input)
    mess: bytearray = bytearray()
    private_key: ECC.EccKey = read_pem_priv_key(key_path, passwd)
    privk_bytes = (len(private_key.public_key().export_key(format="raw")) - 1) // 2
    payload: bytes = bytes(privk_bytes * 2)

    parser.add_section(".signature", payload)

    mess.extend(parser.get_ehdr_bytes())

    for ph, _ in parser.get_program_headers():
        if ph.p_type == PhType.PT_LOAD:
            mess.extend(ph.content(input))

    signer = DSS.new(key=private_key, mode="fips-186-3")
    signature = signer.sign(hash_algo.primitive(mess))
    r, s = bytes(reversed(signature[:privk_bytes])), bytes(reversed(signature[privk_bytes:]))
    payload = r + s

    parser.set_section_content(".signature", payload)


def main():
    args = parse_args()
    with TemporaryFile(mode="r+b") as tmp:
        with open(args.input, "rb") as inf:
            tmp.write(inf.read())
        tmp.seek(0)

        sign_elf_file(tmp, args.private_key, args.passwd.encode(encoding="ascii"), args.hash)

        with open(args.output, "wb") as outf:
            tmp.seek(0)
            outf.write(tmp.read())


if __name__ == "__main__":
    main()
