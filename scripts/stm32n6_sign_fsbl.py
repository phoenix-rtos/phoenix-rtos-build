#!/usr/bin/env python3
#
# Sign FSBL image for STM32N6 secure boot
#
# Copyright 2025 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import argparse, struct, subprocess, hashlib, base64, logging, sys
from typing import BinaryIO, List, NamedTuple, Optional
import Cryptodome.Random
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
from pathlib import Path
from enum import Enum, IntFlag


class AuthenticationError(Exception):
    pass


class ArgumentError(Exception):
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


class AuthParams(NamedTuple):
    private_key: Path
    public_keys: List[Path]
    public_key_index: int
    algorithm: int


class EncryptionParams(NamedTuple):
    encryption_dc: bytes
    encryption_key: Path


class HeaderParams:
    LOAD_ADDRESS_UNUSED = 0xFFFFFFFF
    FSBL_POS = 1024  # Offset at which FSBL image starts
    TOTAL_SIZE = 576  # Total size of all headers
    BEGIN_ZEROS = FSBL_POS - TOTAL_SIZE  # Zeros between headers and FSBL image
    BASE_SIZE = 160  # Size of base header
    ENCR_SIZE = 32  # Size of encryption extension header

    class Ext(IntFlag):
        AUTH = 1 << 0
        ENCR = 1 << 1
        PAD = 1 << 31

    def __init__(
        self,
        image_version: int,
        load_address: int,
        encr_params: Optional[EncryptionParams],
        auth_params: Optional[AuthParams],
    ):
        n_pubKeys = len(auth_params.public_keys) if auth_params is not None else 0
        self.auth_size = 116 + 32 * n_pubKeys
        self.padd_size = self.TOTAL_SIZE - self.BASE_SIZE

        self.image_version = image_version
        self.load_address = load_address
        self.encr_params = encr_params
        self.auth_params = auth_params

        self.ext = self.Ext.PAD
        if auth_params is not None:
            self.ext |= self.Ext.AUTH
            self.padd_size -= self.auth_size

        if encr_params is not None:
            self.ext |= self.Ext.ENCR
            self.padd_size -= self.ENCR_SIZE

    def pad_image(self, img: bytes):
        end_zeros = 16
        img_size = self.BEGIN_ZEROS + len(img) + end_zeros
        end_zeros += 16 - (img_size % 16)
        return bytes(self.BEGIN_ZEROS) + img + bytes(end_zeros)


#### PARSE ARGUMENTS
def parse_args() -> tuple[argparse.Namespace, HeaderParams]:
    parser = argparse.ArgumentParser(description="Sign an STM32N6 FSBL image")
    parser.add_argument("-i", "--image", required=True, type=Path, help="Specify the stripped image file to sign")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Path to output header file")
    parser.add_argument(
        "-iver", "--image-version", type=int, default=0, help="Specify image version for rollback protection"
    )
    parser.add_argument(
        "-la",
        "--load-address",
        type=lambda x: int(x, 16),
        default=HeaderParams.LOAD_ADDRESS_UNUSED,
        help="Specify load address for the image",
    )
    parser.add_argument("-nk", "--no-keys", action="store_true", help="Create header without authentication")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable info and error output")

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-prvk",
        "--private-key",
        type=Path,
        help="Path to unencrypted EC private (.pem) key used to sign image",
    )
    auth_group.add_argument(
        "-pubk-id",
        "--public-key-index",
        help="Specify the index of the public key used to verify signature (0-7)",
    )
    auth_group.add_argument(
        "-pubk",
        "--public-key",
        nargs="+",
        type=Path,
        help="Path to 1-8 EC public keys (.pem) to be accepted for verification",
    )

    encr_group = parser.add_argument_group("Encryption")
    encr_group.add_argument(
        "-enc-dc", "--encryption-dc", help="Specify derivation constant used to derive encryption key"
    )
    encr_group.add_argument(
        "-enc-key", "--encryption-key", type=Path, help="Path to OEM secret file used to derive encryption key"
    )

    args = parser.parse_args()
    if not args.image.is_file():
        raise FileNotFoundError(args.image)

    if args.no_keys:
        auth_params = None
    else:
        # VALIDATE KEYS
        if args.private_key is None:
            raise ArgumentError("private_key not given")

        if args.public_key_index is None:
            raise ArgumentError("public_key_index not given")

        if args.public_key is None:
            raise ArgumentError("public_key not given")

        if not args.private_key.is_file():
            raise FileNotFoundError(args.private_key)

        num_pub_keys = len(args.public_key)
        if num_pub_keys < 1 or num_pub_keys > 8:
            raise ArgumentError(f"Argument error: provide 1 to 8 public keys")

        for pubk in args.public_key:
            if not pubk.is_file():
                raise FileNotFoundError(pubk)

        args.public_key_index = int(args.public_key_index)
        if args.public_key_index < 0 or args.public_key_index >= num_pub_keys:
            raise ArgumentError(
                f"Argument error: public key index needs to be in range [0, num keys - 1 ({num_pub_keys - 1})]"
            )

        validate_keys(args.private_key, args.public_key, args.public_key_index)
        # In the current version we only support algorithm 1 (prime256v1)
        auth_params = AuthParams(args.private_key, args.public_key, args.public_key_index, 1)

    if args.encryption_dc is None and args.encryption_key is None:
        # No encryption requested
        encr_params = None
    elif args.encryption_dc is not None and args.encryption_key is not None:
        if not args.encryption_key.is_file():
            raise FileNotFoundError(args.encryption_key)
        encr_params = EncryptionParams(validate_dc(args.encryption_dc), args.encryption_key)
    else:
        raise ArgumentError(
            "Argument error: for encryption, both OEM secret and derivation constant need to be specified"
        )

    return args, HeaderParams(
        args.image_version,
        args.load_address,
        encr_params,
        auth_params,
    )


# Verify that key files are properly encoded and that the indexed public key is compatible with the private key
def validate_keys(private_key: Path, public_keys: List[Path], public_key_index: int):
    # TODO: Support other key encodings and verify their correctness
    # For now only checking if private key corresponds to public key

    try:
        result = subprocess.run(
            ["openssl", "ec", "-in", str(private_key), "-pubout"], capture_output=True, text=True, check=True
        )
        with open(public_keys[public_key_index], "r") as pbkf:
            if result.stdout != pbkf.read():
                raise AuthenticationError(
                    f"Authentication key ({public_keys[public_key_index]}) doesn't correspond with the private key"
                )
    except subprocess.CalledProcessError as e:
        raise AuthenticationError(
            f"Private key ({private_key}) invalid format\nopenssl returned with {e.returncode}:\n{e.stderr}"
        )


def validate_dc(encryption_dc: str) -> bytes:
    intdc = int(encryption_dc, 0)
    if intdc > 0xFFFFFFFF or intdc < 0:
        raise ValueError("Provide a derivation constant as an unsigned 4 byte integer")
    return struct.pack("<I", intdc)


#### FILE OPERATIONS
def cpy_content(input: BinaryIO, output: BinaryIO) -> None:
    input.seek(0)
    while True:
        chunk = input.read(256)
        if not chunk:
            break
        output.write(chunk)


# Gets the entry point address from the second value in the interrupt vector table
def get_entry_point(img: bytes) -> bytes:
    return img[4:8]


def get_image_checksum(payload: bytes) -> int:
    return sum(payload) & 0xFFFFFFFF


# For now assuming .pem format
def get_pubkey_bytes(key_path: Path) -> bytes:
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


def encrypt_stm_payload(payload: bytes, iv: bytes, encr_params: EncryptionParams) -> bytes:
    with open(encr_params.encryption_key, "rb") as f:
        edmk = f.read()

    # Magic numbers that are set by ST
    M = bytearray(32)
    M[3] = 0x01
    M[0x04:0x17] = b"BL2 encryption key."
    M[0x1F] = 0x80
    M[0x18:0x1C] = encr_params.encryption_dc

    fsbl_key = aes_cmac_pfr_128(edmk, M)
    cipher = AES.new(fsbl_key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(payload)


#### HEADER FUNCTIONS
def header_base(
    sig_file: BinaryIO,
    img_size: int,
    entry_point: bytes,
    img_checksum: int,
    header: HeaderParams,
) -> None:
    sig_file.seek(0)
    sig_file.write(b"\x53\x54\x4d\x32")  # Magic number
    sig_file.write(bytes(96))  # ECDSA Signature (zero bytes)
    sig_file.write(struct.pack("<I", img_checksum))  # Image Checksum
    sig_file.write(b"\x00\x03\x02\x00")  # Header version
    sig_file.write(struct.pack("<I", img_size))  # Image size
    sig_file.write(entry_point)  # Entry point
    sig_file.write(bytes(4))  # Reserved1
    sig_file.write(struct.pack("<I", header.load_address))  # Load address
    sig_file.write(bytes(4))  # Reserved2
    sig_file.write(struct.pack("<I", header.image_version))  # Image version
    sig_file.write(struct.pack("<I", header.ext))  # Extension flags
    sig_file.write(struct.pack("<I", header.TOTAL_SIZE - header.BASE_SIZE))  # Post header length
    sig_file.write(struct.pack("<I", 16))  # Binary type
    sig_file.write(bytes(8))  # PAD
    sig_file.write(bytes(4))  # Nonsec payload length
    sig_file.write(bytes(4))  # Nonsec payload hash


def header_auth(sig_file: BinaryIO, header: HeaderParams):
    if header.auth_params is None:
        return

    algo_bytes = struct.pack("<I", header.auth_params.algorithm)
    sig_file.write(b"\x53\x54\x00\x02")  # Magic number
    sig_file.write(struct.pack("<I", header.auth_size))  # Extension header length
    sig_file.write(struct.pack("<I", header.auth_params.public_key_index))  # Public key index (which one to use)
    sig_file.write(struct.pack("<I", len(header.auth_params.public_keys)))  # Number of public keys in table
    sig_file.write(algo_bytes)  # ECDSA Algorithm num (1-4)

    pbk_path = header.auth_params.public_keys[header.auth_params.public_key_index]
    sig_file.write(get_pubkey_bytes(pbk_path) + bytes(32))  # Verification public key (padding for ECDSA 256)

    # Public key hashes
    for pubkey_path in header.auth_params.public_keys:
        sig_file.write(hashlib.sha256(algo_bytes + get_pubkey_bytes(pubkey_path)).digest())


def header_encr(sig_file: BinaryIO, plain_hash: Optional[bytes], header: HeaderParams):
    if header.encr_params is None or plain_hash is None:
        return

    sig_file.write(b"\x53\x54\x00\x01")  # Magic number
    sig_file.write(struct.pack("<I", header.ENCR_SIZE))  # Extension header length
    sig_file.write(struct.pack("<I", 128))  # Key size
    sig_file.write(header.encr_params.encryption_dc)  # Derivation constant
    sig_file.write(plain_hash)  # 128 msb bits of of plain payload SHA256 hash


def header_padd(sig_file: BinaryIO, header: HeaderParams):
    sig_file.write(b"\x53\x54\xff\xff")  # Magic number
    sig_file.write(struct.pack("<I", header.padd_size))  # Extension header length
    rand = Cryptodome.Random.get_random_bytes(header.padd_size - 8)
    sig_file.write(rand)  # Padding bytes


def add_payload(sig_file: BinaryIO, payload: bytes, header: HeaderParams) -> None:
    sig_file.seek(header.TOTAL_SIZE)
    sig_file.write(payload)


def add_signature(sig_file: BinaryIO, payload: bytes, header: HeaderParams) -> None:
    if header.auth_params is None:
        return

    sigblock = bytearray()
    sig_file.flush()
    sig_file.seek(104)
    sigblock.extend(sig_file.read(48))
    sig_file.seek(header.BASE_SIZE)
    sigblock.extend(sig_file.read(header.TOTAL_SIZE - header.BASE_SIZE))
    sigblock.extend(payload)

    try:
        hash_content = hashlib.sha256(sigblock).digest()
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(header.auth_params.private_key)],
            check=True,
            capture_output=True,
            input=hash_content,
        )
        sig_file.seek(4)
        sig_file.write(strip_ecdsa_der(result.stdout))
    except subprocess.CalledProcessError as e:
        raise AuthenticationError(f"Failed to sign image.\nopenssl returned with {e.returncode}:\n{e.stderr}")


# Signing function
def sign_fsbl(input_img: BinaryIO, output_img: BinaryIO, header: HeaderParams) -> None:
    img = input_img.read()
    payload = header.pad_image(img)
    entry_point = get_entry_point(img)
    if header.encr_params is not None:
        plain_hash = hashlib.sha256(payload).digest()[:16]
        payload = encrypt_stm_payload(payload, plain_hash, header.encr_params)
    else:
        plain_hash = None

    image_size = len(payload)
    check_sum = get_image_checksum(payload)

    # At first sign without signature
    header_base(output_img, image_size, entry_point, check_sum, header)
    header_auth(output_img, header)
    header_encr(output_img, plain_hash, header)
    header_padd(output_img, header)
    add_payload(output_img, payload, header)
    add_signature(output_img, payload, header)


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
        with open(args.image, "rb") as input_img, open(args.output, "w+b") as output_img:
            sign_fsbl(input_img, output_img, header)
        logger.info("Signing successful!")
    except Exception as e:
        logger.error("%s: %s", type(e).__name__, e)
        exit(1)


if __name__ == "__main__":
    main()
