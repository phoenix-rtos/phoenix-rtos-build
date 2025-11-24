#!/usr/bin/env python3
#
# Sign FSBL image for STM32N6 secure boot
#
# Copyright 2025 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import traceback, argparse, struct, os, subprocess, hashlib, base64, logging, sys
from typing import BinaryIO
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from pathlib import Path
from enum import Enum


class AuthenticationError(Exception):
    pass


class Color(Enum):
    DEFAULT = "\033[39m"
    MAGENTA = "\033[95m"
    LBLUE = "\033[94m"
    LCYAN = "\033[96m"
    LGREEN = "\033[92m"
    YELLOW = "\033[93m"
    LRED = "\033[91m"
    ENDC = "\033[0m"


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: Color.LGREEN,
        logging.ERROR: Color.LRED,
    }

    def format(self, record):
        message = super().format(record)
        return f"{self.COLORS.get(record.levelno, Color.DEFAULT).value}{message}{Color.ENDC.value}"


class HeaderParams:
    def __init__(self, num_pub_keys: int, image: Path, encryption: bool):
        self.fsbl_pos = 1024
        self.end_zeros = 16
        self.beg_zeros = 448

        self.totl_size = 576
        self.base_size = 160
        self.auth_size = 116 + 32 * num_pub_keys
        self.encr_size = 32
        self.padd_size = self.totl_size - self.base_size - self.auth_size

        if encryption:
            self.padd_size -= self.encr_size

        img_size = os.path.getsize(image) + self.beg_zeros + self.end_zeros
        self.end_zeros += 16 - (img_size % 16)


#### PARSE ARGUMENTS
def parse_args() -> tuple[argparse.Namespace, HeaderParams]:
    parser = argparse.ArgumentParser(description="Sign an STM32N6 FSBL image")
    parser.add_argument("-i", "--image", required=True, type=Path, help="Specify the stripped image file to sign")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Path to output header file")
    parser.add_argument("-la", "--load-address", required=True, help="Specify a load address of image")
    parser.add_argument("-iver", "--image-version", default="0", help="Specify image version")
    parser.add_argument(
        "-prvk",
        "--private-key",
        required=True,
        type=Path,
        help="Path to unencrypted EC private (.pem) key used to sign image",
    )
    parser.add_argument(
        "-pubk-id",
        "--public-key-index",
        required=True,
        help="Specify the index of the public key used to verify signature (0-7)",
    )
    parser.add_argument(
        "-pubk",
        "--public-key",
        nargs="+",
        required=True,
        type=Path,
        help="Path to 1-8 EC public keys (.pem) to be accepted for verification",
    )
    parser.add_argument(
        "-enc-dc", "--encryption-dc", nargs=1, help="Specify derivation constant used to derive encryption key"
    )
    parser.add_argument(
        "-enc-key", "--encryption-key", type=Path, help="Path to OEM secret file used to derive encryption key"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable info and error output")
    args = parser.parse_args()

    if not args.image.is_file():
        raise ValueError(f"Argument error: failed to open {args.image}")

    # VALIDATE KEYS
    if not args.private_key.is_file():
        raise ValueError(f"Argument error: failed to open {args.private_key}")
    if (num_pub_keys := len(args.public_key)) < 1 or num_pub_keys > 8:
        raise ValueError(f"Argument error: provide 1 to 8 public keys")
    for pubk in args.public_key:
        if not pubk.is_file():
            raise ValueError(f"Argument error: failed to open {pubk}")
    args.public_key_index = int(args.public_key_index)
    if args.public_key_index < 0 or args.public_key_index >= num_pub_keys:
        raise ValueError(
            f"Argument error: public key index needs to be in range [0, num keys - 1 ({num_pub_keys - 1})]"
        )
    validate_keys(args.private_key, args.public_key, args.public_key_index)

    args.load_address = struct.pack("<I", int(args.load_address, 16))
    args.image_version = struct.pack("<I", int(args.image_version))
    args.algorithm = struct.pack("<I", 1)

    # ENCRYPTION
    args.ext_flags = 0x80000001
    if args.encryption_dc == None and args.encryption_key == None:
        args.encrypt = False
    elif args.encryption_dc != None and args.encryption_key != None:
        args.encryption_dc = validate_dc(args.encryption_dc[0])
        if not args.encryption_key.is_file():
            raise ValueError(f"Argument error: failed to open {args.encryption_key}")
        args.encrypt = True
        args.ext_flags = 0x80000003
    else:
        raise ValueError("Argument error: for encryption, both OEM secret and derivation constant need to be specified")

    header_params = HeaderParams(num_pub_keys, args.image, args.encrypt)
    return args, header_params


# Verify that key files are properly encoded and that the indexed public key is compatible with the private key
def validate_keys(private_key: Path, public_keys: list[Path], public_key_index: int):
    # TODO: Support other key encodings and verify their correctness
    # For now only checking if private key corresponds to public key

    try:
        result = subprocess.run(["openssl", "ec", "-in", str(private_key), "-pubout"], capture_output=True, text=True)
        with open(public_keys[public_key_index], "r") as pbkf:
            if result.stdout != pbkf.read():
                raise AuthenticationError(
                    f"Authentication error: authentication key ({public_keys[public_key_index]}) doesn't correspond with the private key"
                )
    except subprocess.CalledProcessError as e:
        raise AuthenticationError(
            f"Authentication error: authentication key ({public_keys[public_key_index]}) invalid format"
        )


def validate_dc(encryption_dc: str) -> bytes:
    intdc = int(encryption_dc, 0)
    if intdc > 0xFFFFFFFF or intdc < 0:
        raise ValueError("Argument error: provide a derivation constant as an unsigned 4 byte integer")
    return intdc.to_bytes(4, byteorder="little")


#### FILE OPERATIONS
def cpy_content(input: BinaryIO, output: BinaryIO) -> None:
    input.seek(0)
    while True:
        chunk = input.read(256)
        if not chunk:
            break
        output.write(chunk)


# Gets the entry point address from the second value in the interrupt vector table
def get_entry_point(raw_image: BinaryIO) -> bytes:
    raw_image.seek(4)
    return raw_image.read(4)


def get_image_checksum(payload: bytes) -> bytes:
    chksum: int = 0x00
    for byte in payload:
        chksum = (chksum + byte) & 0xFFFFFFFF
    return struct.pack("<I", chksum)


# For now assuming .pem format
def get_pubkey_bytes(key_path: str) -> bytes:
    with open(key_path, "rb") as fk:
        b64data = b"".join(list(map(lambda line: line.replace(b"\n", b""), fk.readlines()[1:-1])))
        # Skipping 27 bytes of metadata
        return base64.standard_b64decode(b64data)[27:]


# Removes ASN.1/DER metadata from ecdsa signature
def strip_ecdsa_der(signature: bytes) -> bytes:
    r_len = signature[3]
    r_bytes = signature[4 : 4 + r_len]
    if r_bytes[0] == 0x00:
        r_bytes = r_bytes[1:]
    signature = signature[5 + r_len :]
    s_len = signature[0]
    s_bytes = signature[1 : 1 + s_len]
    if s_bytes[0] == 0x00:
        s_bytes = s_bytes[1:]

    return r_bytes + s_bytes + bytes(32)


def strip_ecdsa_der_old(signature_path: str) -> bytes:
    with open(signature_path, "rb") as f:
        f.seek(3)
        r_len = int.from_bytes(f.read(1))
        r_bytes = f.read(r_len)
        if r_bytes[0] == 0x00:
            r_bytes = r_bytes[1:]
        f.read(1)  # skips 0x02 (INT) byte
        s_len = int.from_bytes(f.read(1))
        s_bytes = f.read(s_len)
        if s_bytes[0] == 0x00:
            s_bytes = s_bytes[1:]

        return r_bytes + s_bytes + bytes(32)


#### CRYPTOGRAPHY
def aes_cmac_pfr_128(var_key: bytes, M: bytes):
    if len(var_key) == 16:
        key = var_key
    else:
        key = CMAC.new(bytes(16), ciphermod=AES).update(var_key).digest()
    return CMAC.new(key, ciphermod=AES).update(M).digest()


def encrypt_stm_payload(payload: bytes, iv: bytes, enc_key_file: Path, derivation_const: bytes) -> bytes:
    with open(enc_key_file, "rb") as f:
        edmk = f.read()

    # Magic numbers that are set by ST
    M = bytearray(32)
    M[3] = 0x01
    M[0x04:0x17] = b"BL2 encryption key."
    M[0x1F] = 0x80
    M[0x18:0x1C] = derivation_const

    fsbl_key = aes_cmac_pfr_128(edmk, M)
    cipher = AES.new(fsbl_key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(payload)


#### HEADER FUNCTIONS
def header_base(
    sig_file: BinaryIO,
    img_size: int,
    entry_point: bytes,
    img_checksum: bytes,
    args: argparse.Namespace,
    header: HeaderParams,
) -> None:
    sig_file.seek(0)
    sig_file.write(b"\x53\x54\x4d\x32")  # Magic number
    sig_file.write(bytes(96))  # ECDSA Signature (zero bytes)
    sig_file.write(img_checksum)  # Image Checksum
    sig_file.write(b"\x00\x03\x02\x00")  # Header version
    sig_file.write(struct.pack("<I", img_size))  # Image size
    sig_file.write(entry_point)  # Entry point
    sig_file.write(bytes(4))  # Reserved1
    sig_file.write(args.load_address)  # Load address
    sig_file.write(bytes(4))  # Reserved2
    sig_file.write(args.image_version)  # Image version
    sig_file.write(struct.pack("<I", args.ext_flags))  # Extension flags
    sig_file.write(struct.pack("<I", header.totl_size - header.base_size))  # Post header length
    sig_file.write(struct.pack("<I", 16))  # Binary type
    sig_file.write(bytes(8))  # PAD
    sig_file.write(bytes(4))  # Nonsec payload length
    sig_file.write(bytes(4))  # Nonsec payload hash


def header_auth(sig_file: BinaryIO, args: argparse.Namespace, header: HeaderParams):
    sig_file.write(b"\x53\x54\x00\x02")  # Magic number
    sig_file.write(struct.pack("<I", header.auth_size))  # Extension header length
    sig_file.write(struct.pack("<I", args.public_key_index))  # Public key index (which one to use)
    sig_file.write(struct.pack("<I", len(args.public_key)))  # Number of public keys in table
    sig_file.write(args.algorithm)  # ECDSA Algorithm num (1-4)

    pbk_path = args.public_key[args.public_key_index]
    sig_file.write(get_pubkey_bytes(pbk_path) + bytes(32))  # Verification public key (padding for ECDSA 256)

    # Public key hashes
    for pubkey_path in args.public_key:
        sig_file.write(hashlib.sha256(args.algorithm + get_pubkey_bytes(pubkey_path)).digest())


def header_encr(sig_file: BinaryIO, plain_hash: bytes, args: argparse.Namespace, header: HeaderParams):
    sig_file.write(b"\x53\x54\x00\x01")  # Magic number
    sig_file.write(struct.pack("<I", header.encr_size))  # Extension header length
    sig_file.write(struct.pack("<I", 128))  # Key size
    sig_file.write(args.encryption_dc)  # Derivation constant
    sig_file.write(plain_hash)  # 128 msb bits of of plain payload SHA256 hash


def header_padd(sig_file: BinaryIO, padd_header_size: int):
    sig_file.write(b"\x53\x54\xff\xff")  # Magic number
    sig_file.write(struct.pack("<I", padd_header_size))  # Extension header length
    sig_file.write(os.urandom(padd_header_size - 8))  # Padding bytes


def add_payload(sig_file: BinaryIO, payload: bytes, header: HeaderParams) -> None:
    sig_file.seek(header.totl_size)
    sig_file.write(payload)


def add_signature(sig_file: BinaryIO, payload: bytes, args: argparse.Namespace, header: HeaderParams) -> None:
    sigblock = bytearray()
    sig_file.flush()
    sig_file.seek(104)
    sigblock.extend(sig_file.read(48))
    sig_file.seek(header.base_size)
    sigblock.extend(sig_file.read(header.totl_size - header.base_size))
    sigblock.extend(payload)

    try:
        hash_content = hashlib.sha256(sigblock).digest()
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", args.private_key],
            check=True,
            capture_output=True,
            input=hash_content,
        )
        sig_file.seek(4)
        sig_file.write(strip_ecdsa_der(result.stdout))
    except subprocess.CalledProcessError as e:
        raise AuthenticationError(f"Authentication error: failed to sign image due to invalid key")


# Signing function
def sign_fsbl(args: argparse.Namespace, header: HeaderParams) -> None:
    with open(args.output, "w+b") as sig_file, open(args.image, "rb") as img_file:

        payload = bytes(header.beg_zeros) + img_file.read() + bytes(header.end_zeros)
        if args.encrypt:
            plain_hash = hashlib.sha256(payload).digest()[:16]
            payload = encrypt_stm_payload(payload, plain_hash, args.encryption_key, args.encryption_dc)
        image_size = len(payload)
        entry_point = get_entry_point(img_file)
        check_sum = get_image_checksum(payload)

        # At first sign without signature
        header_base(sig_file, image_size, entry_point, check_sum, args, header)
        header_auth(sig_file, args, header)
        if args.encrypt:
            header_encr(sig_file, plain_hash, args, header)
        header_padd(sig_file, header.padd_size)

        add_payload(sig_file, payload, header)

        add_signature(sig_file, payload, args, header)


def configure_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(ColorFormatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def main() -> None:
    logger = configure_logger()
    try:
        args, header = parse_args()
        if args.verbose:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.CRITICAL)
        sign_fsbl(args, header)
        logger.info("Signing successful!")
    except Exception as e:
        logger.error(e)


if __name__ == "__main__":
    main()
