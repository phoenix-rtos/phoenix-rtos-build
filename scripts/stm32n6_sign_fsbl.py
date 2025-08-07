#!/usr/bin/env python3
#
# Sign FSBL image for STM32N6 secure boot
#
# Copyright 2025 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import  argparse, struct, os, subprocess
from typing import BinaryIO
from stm32n6_log_util import *
import hashlib
import base64
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


FSBL_POS = 1024         # Payload starts at 1024
END_ZEROS = 16          # Payload padded with >=16 zeros so that the full image size is a multiple of 16
BEG_ZEROS = 448         # Payload padded with 448 zeros at the beginning so that first real byte is at pos 1024
 
HEADER_TOTL_SIZE = 576
HEADER_BASE_SIZE = 160
HEADER_AUTH_SIZE = 116  # Modified later
HEADER_ENCR_SIZE = 32
HEADER_PADD_SIZE = -1   # Modified later


#### PARSE ARGUMENTS
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sign an STM32N6 FSBL image")
    parser.add_argument("-i", "--image", required=True, help="Specify the stripped image file to sign")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", required=True, help="Path to output header file")
    parser.add_argument("-la", "--load-address", required=True, help="Specify a load address of image")
    parser.add_argument("-iver", "--image-version", default="0", help="Specify image version")
    parser.add_argument("-prvk", "--private-key", required=True, help="Path to unencrypted EC private (.pem) key used to sign image")
    parser.add_argument("-pubk-id", "--public-key-index", required=True, help="Specify the index of the public key used to verify signature (0-7)")
    parser.add_argument("-pubk", "--public-key", nargs="+", required=True, help="Path to 1-8 EC public keys (.pem) to be accepted for verification")
    parser.add_argument("-enc-dc", "--encryption-dc", nargs=1, help="Specify derivation constant used to derive encryption key")
    parser.add_argument("-enc-key", "--encryption-key", nargs=1, help="Path to OEM secret file used to derive encryption key")
    args = parser.parse_args()

    global DEBUG_LOG_ENABLED, HEADER_AUTH_SIZE, HEADER_PADD_SIZE, END_ZEROS
    DEBUG_LOG_ENABLED = args.verbose

    check_bin_file(args.image)

    # VALIDATE KEYS 
    check_bin_file(args.private_key)
    if (l := len(args.public_key)) < 1 or l > 8:
        error(f"Argument error: provide 1 to 8 public keys")
    for pubk in args.public_key:
        check_bin_file(pubk)
    args.public_key_index = int(args.public_key_index)
    if args.public_key_index < 0 or args.public_key_index >= l:
        error(f"Argument error: public key index needs to be in range [0, num keys - 1 ({l - 1})]") 
    validate_keys(args.private_key, args.public_key, args.public_key_index)

    args.load_address = struct.pack("<I", int(args.load_address, 16))
    args.image_version = struct.pack("<I", int(args.image_version))
    args.algorithm = struct.pack("<I", 1)

    # ENCRYPTION
    args.ext_flags = 0x80000001
    if args.encryption_dc == None and args.encryption_key == None:
        args.encrypt = False
    elif args.encryption_dc != None and args.encryption_key != None:
        args.encryption_key = args.encryption_key[0]
        args.encryption_dc = validate_dc(args.encryption_dc[0])
        check_bin_file(args.encryption_key)
        args.encrypt = True
        args.ext_flags = 0x80000003
    else:
        error("Argument error: for encryption, both OEM secret and derivation constant need to be specified")
    
    HEADER_AUTH_SIZE += l * 32
    HEADER_PADD_SIZE = HEADER_TOTL_SIZE - HEADER_BASE_SIZE - HEADER_AUTH_SIZE
    if args.encrypt:
        HEADER_PADD_SIZE -= HEADER_ENCR_SIZE

    img_size = os.path.getsize(args.image) + BEG_ZEROS + END_ZEROS
    END_ZEROS += (16 - (img_size % 16))

    return args


# Verify that key files are properly encoded and that the indexed public key is compatible with the private key
def validate_keys(private_key: str, public_keys: list[str], public_key_index: int):
    # TODO: Support other key encodings and verify their correctness
    # For now only checking if private key corresponds to public key

    subprocess.run(["openssl", "ec", "-in", private_key, "-pubout", "-out", ".sign_pubkey.pem"], capture_output=True)
    with open(".sign_pubkey.pem", "rb") as tmp:
        with open(public_keys[public_key_index], "rb") as pbkf:
            assert tmp.read() == pbkf.read()
    os.remove(".sign_pubkey.pem")


def validate_dc(encryption_dc: str) -> bytes:
    intdc = int(encryption_dc, 0)
    if intdc > 0xFFFFFFFF or intdc < 0:
        error("Argument error: provide a derivation constant as an unsigned 4 byte integer")
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
        chksum = (chksum + byte) & 0xFFFFFFFFF
    return struct.pack("<I", chksum)


# For now assuming .pem format
def get_pubkey_bytes(key_path: str) -> bytes:
    with open(key_path, "rb") as fk:
        b64data = b"".join(list(map(lambda line: line.replace(b"\n", b""), fk.readlines()[1:-1])))
        # Skipping 27 bytes of metadata
        return base64.standard_b64decode(b64data)[27:]


# Removes ANS.1/DER metadata from ecdsa signature
def strip_ecdsa_der(signature_path: str) -> bytes:
    with open(signature_path, "rb") as f:
        f.seek(3)
        r_len = int.from_bytes(f.read(1))
        r_bytes = f.read(r_len)
        if r_bytes[0] == 0x00:
            r_bytes = r_bytes[1:]
        f.read(1) # skips 0x02 (INT) byte
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
        key = CMAC.new(bytes(16), ciphermod=AES)\
                  .update(var_key)\
                  .digest()
    return CMAC.new(key, ciphermod=AES)\
               .update(M)\
               .digest()


def encrypt_stm_payload(payload: bytes, iv: bytes, enc_key_file: str, derivation_const: bytes) -> bytes:
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
def header_base(sig_file: BinaryIO, img_size: int, entry_point: bytes, img_checksum: bytes, args: argparse.Namespace) -> None:
    sig_file.seek(0)
    sig_file.write(b'\x53\x54\x4d\x32')                                     # Magic number
    sig_file.write(bytes(96))                                               # ECDSA Signature (zero bytes)
    sig_file.write(img_checksum)                                            # Image Checksum
    sig_file.write(b'\x00\x03\x02\x00')                                     # Header version
    sig_file.write(struct.pack("<I", img_size))                             # Image size
    sig_file.write(entry_point)                                             # Entry point
    sig_file.write(bytes(4))                                                # Reserved1
    sig_file.write(args.load_address)                                       # Load address
    sig_file.write(bytes(4))                                                # Reserved2
    sig_file.write(args.image_version)                                      # Image version
    sig_file.write(struct.pack("<I", args.ext_flags))                       # Extension flags
    sig_file.write(struct.pack("<I", HEADER_TOTL_SIZE - HEADER_BASE_SIZE))  # Post header length
    sig_file.write(struct.pack("<I", 16))                                   # Binary type
    sig_file.write(bytes(8))                                                # PAD
    sig_file.write(bytes(4))                                                # Nonsec payload length 
    sig_file.write(bytes(4))                                                # Nonsec payload hash


def header_auth(sig_file: BinaryIO, args: argparse.Namespace):
    sig_file.write(b'\x53\x54\x00\x02')                      # Magic number
    sig_file.write(struct.pack("<I", HEADER_AUTH_SIZE))      # Extension header length
    sig_file.write(struct.pack("<I", args.public_key_index)) # Public key index (which one to use)
    sig_file.write(struct.pack("<I", len(args.public_key)))  # Number of public keys in table
    sig_file.write(args.algorithm)                           # ECDSA Algorithm num (1-4)

    pbk_path = args.public_key[args.public_key_index]
    sig_file.write(get_pubkey_bytes(pbk_path) + bytes(32))   # Verification public key (padding for ECDSA 256)

    # Public key hashes
    for pubkey_path in args.public_key:
        sig_file.write(hashlib.sha256(args.algorithm + get_pubkey_bytes(pubkey_path)).digest())


def header_encr(sig_file: BinaryIO, plain_hash: bytes, args: argparse.Namespace):
    sig_file.write(b"\x53\x54\x00\x01")                      # Magic number
    sig_file.write(struct.pack("<I", HEADER_ENCR_SIZE))      # Exntension header length
    sig_file.write(struct.pack("<I", 128))                   # Key size
    sig_file.write(args.encryption_dc)                       # Derivation constant
    sig_file.write(plain_hash)                               # 128 msb bits of of plain payload SHA256 hash


def header_padd(sig_file: BinaryIO, padd_header_size: int):
    sig_file.write(b'\x53\x54\xff\xff')                      # Magic number
    sig_file.write(struct.pack("<I", padd_header_size))      # Extension header length
    sig_file.write(os.urandom(padd_header_size - 8))         # Padding bytes


def add_payload(sig_file: BinaryIO, payload: bytes) -> None:
    sig_file.seek(HEADER_TOTL_SIZE)
    sig_file.write(payload)


def add_signature(sig_file: BinaryIO, payload: bytes, args: argparse.Namespace) -> None:
    sigblock = bytearray()
    sig_file.flush()
    sig_file.seek(104)
    sigblock.extend(sig_file.read(48))
    sig_file.seek(HEADER_BASE_SIZE)
    sigblock.extend(sig_file.read(HEADER_TOTL_SIZE - HEADER_BASE_SIZE))
    sigblock.extend(payload)

    hash_file: str = ".tmp_hash_file"
    signature_file: str = ".sign_ecdsa_der"
    with open(hash_file, "wb") as hf:
        hf.write(hashlib.sha256(sigblock).digest())
    
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", args.private_key, "-in", hash_file, "-out", signature_file], \
                   check=True, capture_output=True, text=True)
    sig_file.seek(4)
    sig_file.write(strip_ecdsa_der(signature_file))
    os.remove(hash_file)
    os.remove(signature_file)


def main() -> None:
    args = parse_args()
    sig_file = open(args.output, "w+b")
    img_file = open(args.image, "rb")

    payload = bytes(BEG_ZEROS) + img_file.read() + bytes(END_ZEROS)
    if args.encrypt:
        plain_hash = hashlib.sha256(payload).digest()[:16]
        payload = encrypt_stm_payload(payload, plain_hash, args.encryption_key, args.encryption_dc)
    image_size = len(payload)
    entry_point = get_entry_point(img_file)
    check_sum = get_image_checksum(payload)

    # At first sign without signature
    header_base(sig_file, image_size, entry_point, check_sum, args)
    header_auth(sig_file, args)
    if args.encrypt:
        header_encr(sig_file, plain_hash, args)
    header_padd(sig_file, HEADER_PADD_SIZE)

    add_payload(sig_file, payload)

    add_signature(sig_file, payload, args)

    img_file.close()
    sig_file.close()

    info_log("Signing successfull!", bcolors.OKGREEN)


if __name__ == "__main__":
    main()

