#!/usr/bin/env python3
#
# Script for fixup of IMX6ULL system images and signing images using IMX CST tool
#
# Copyright 2026 Phoenix Systems
# Author: Jacek Maksymowicz
#

import argparse
from enum import IntEnum
import logging
import os
import shutil
import subprocess
import tempfile
from typing import BinaryIO, Iterable, NamedTuple, Optional
import configparser
from pathlib import Path

# 8 KB should be enough even for 4096-bit RSA signatures
CSF_MAX_SIZE = 8192
DCD_WRITE_ADDR = 0x00910000
IVT_ALIGNMENT = 32
DEFAULT_IMAGE_NAME = "phoenix-kernel.img"
PAD_BYTE = b"\0"


class IvtOffsets(IntEnum):
    "Byte offsets of data fields within IVT header"

    hdr = 0 * 4
    entry = 1 * 4
    dcd = 3 * 4
    boot_data = 4 * 4
    ivt_self = 5 * 4
    csf = 6 * 4


class BootDataOffsets(IntEnum):
    "Byte offsets of data fields within boot data header"

    load_addr = 0 * 4
    size = 1 * 4
    plugin = 2 * 4


def parse_args():
    def add_sign_arguments(parser: argparse.ArgumentParser):
        parser.add_argument("--cst-bin", help="Path to CST tool binary", type=Path, required=True)
        parser.add_argument(
            "--cst-dir",
            help="Path to directory that contains CST template (phoenix.cst) and certificates",
            type=Path,
            required=True,
        )
        parser.add_argument(
            "--sig-max-size", help="Maximum size of signature (CSF)", type=lambda x: int(x, 0), default=CSF_MAX_SIZE
        )

    def add_kernel_arguments(parser: argparse.ArgumentParser):
        parser.add_argument("--cross", default=os.environ.get("CROSS"), help="Toolchain prefix")
        parser.add_argument("--kernel-elf", help="Kernel .elf file", type=Path, required=True)

    prefix_boot = os.environ.get("PREFIX_BOOT")
    default_image = Path(prefix_boot) / DEFAULT_IMAGE_NAME if prefix_boot is not None else None
    fc = argparse.ArgumentDefaultsHelpFormatter

    parser = argparse.ArgumentParser("imx6ull secure boot image generator", formatter_class=fc)
    parser.add_argument("--temp-dir", default=os.environ.get("PREFIX_BUILD"), help="Temporary directory path")
    parser.add_argument(
        "--image", help="Image to modify", type=Path, default=default_image, required=(default_image is None)
    )
    parser.add_argument("--serial-dl", help="Create image for serial download", action="store_true")
    parser.add_argument("--verbose", help="Verbose logging", action="store_true")

    subparsers = parser.add_subparsers(dest="action")
    k_parser = subparsers.add_parser("kernel", help="Finalize kernel image", formatter_class=fc)
    add_kernel_arguments(k_parser)

    sk_parser = subparsers.add_parser("sign-kernel", help="Finalize and sign kernel image", formatter_class=fc)
    add_sign_arguments(sk_parser)
    add_kernel_arguments(sk_parser)

    sb_parser = subparsers.add_parser("sign-bin", help="Sign raw binary image", formatter_class=fc)
    add_sign_arguments(sb_parser)
    sb_parser.add_argument(
        "--load-addr",
        help="Binary load address (may be determined automatically from IVT boot data)",
        type=lambda x: int(x, 0),
    )
    sb_parser.add_argument(
        "--ivt-offset", help="IVT offset (if not given, IVT footer will be created)", type=lambda x: int(x, 0)
    )

    return parser.parse_args()


def get_symbols(readelf: str, elf: str):
    "Read symbols from ELF file, return dict mapping name of symbol to address"
    cmd_out = subprocess.check_output([readelf, "-sW", elf]).decode("utf-8")
    lines = filter(lambda x: len(x) >= 8 and x[2].isdigit(), map(lambda x: x.split(), cmd_out.splitlines()))
    return dict(map(lambda x: (x[7], int(x[1], 16)), lines))


def get_u32_from_file(file: BinaryIO, offset: int, big_endian: bool = False):
    "Get a little-endian 32-bit number from the given byte offset in file"
    prev_offset = file.tell()
    file.seek(offset)
    b = file.read(4)
    file.seek(prev_offset)
    assert len(b) == 4
    return int.from_bytes(b, "big" if big_endian else "little", signed=False)


def round_up(x: int, factor: int):
    return ((x + factor - 1) // factor) * factor


def quote_path(p: Path):
    quote_trans = str.maketrans({'"': '\\"'})
    return '"' + str(p.absolute()).translate(quote_trans) + '"'


class SignArgs(NamedTuple):
    cst_bin: Path
    cst_dir: Path
    max_size: int
    temp_dir: Optional[Path]


class KernelArgs(NamedTuple):
    readelf: str
    elf: Path


class BinArgs(NamedTuple):
    load_addr: int
    ivt_offset: Optional[int]


class VerificationBlock(NamedTuple):
    load_addr: int
    file_offset: int
    size: int
    file: Path


def sign_file(sign: SignArgs, img_out: Path, blocks: Iterable[VerificationBlock], csf_size: int):
    logging.info("Signing image %s", img_out.name)
    cst_path = sign.cst_dir / "phoenix.cst"
    if not cst_path.is_file():
        raise FileNotFoundError(str(cst_path))

    cst = configparser.ConfigParser()
    success = cst.read(cst_path)
    if not success:
        raise RuntimeError(f"Could not read CST file: {cst_path}")

    cst["Authenticate Data"]["Blocks"] = ", ".join(
        map(lambda x: f"0x{x.load_addr:08x} 0x{x.file_offset:08x} 0x{x.size:08x} {quote_path(x.file)}", blocks)
    )

    with (
        tempfile.NamedTemporaryFile("w", suffix=".cst", dir=sign.temp_dir, delete_on_close=False) as filled_cst,
        tempfile.NamedTemporaryFile("w", suffix=".bin", dir=sign.temp_dir, delete_on_close=False) as sig_file,
    ):
        logging.debug("Filled CST in %s, signature in %s", filled_cst.name, sig_file.name)
        cst.write(filled_cst, True)
        filled_cst.close()
        sig_file.close()
        sig_file_path = Path(sig_file.name).absolute()
        filled_cst_path = Path(filled_cst.name).absolute()
        cmd_result = subprocess.run(
            [str(sign.cst_bin), "--o", str(sig_file_path), "--i", str(filled_cst_path)],
            cwd=sign.cst_dir,
            capture_output=True,
        )

        output = cmd_result.stdout.decode("utf-8").strip() + "\n" + cmd_result.stderr.decode("utf-8").strip()
        if cmd_result.returncode != 0:
            raise RuntimeError(f"CST tool failed with code {cmd_result.returncode}: {output}")
        else:
            logging.debug(output)

        sig_bin = sig_file_path.read_bytes()

    sig_size = len(sig_bin)
    if sig_size > csf_size:
        raise RuntimeError(f"CSF signature is larger than reserved size (max {csf_size}, got {sig_size})")

    if sig_size == 0:
        raise RuntimeError(f"Returned signature has size 0")

    pad_size = csf_size - sig_size
    with open(img_out, "ab") as f:
        f.write(sig_bin)
        # Not sure why, but padding to maximum reserved size seems to be necessary for Flash boot.
        # Perhaps reading from uninitialized Flash causes a failure?
        f.write(PAD_BYTE * pad_size)


def detect_load_address(image: Path, ivt_offset: int):
    with open(image, "rb") as f:
        ivt_self = get_u32_from_file(f, ivt_offset + IvtOffsets.ivt_self)
        boot_data_ptr = get_u32_from_file(f, ivt_offset + IvtOffsets.boot_data)
        if boot_data_ptr == 0:
            return None

        boot_data_offset = boot_data_ptr - ivt_self + ivt_offset
        return get_u32_from_file(f, boot_data_offset + BootDataOffsets.load_addr)


def process_image(
    img_in: Path,
    img_out: Path,
    serial_dl: bool,
    sign: Optional[SignArgs],
    kernel: Optional[KernelArgs],
    bin: Optional[BinArgs],
):
    csf_size = sign.max_size if sign is not None else 0

    load_addr = None
    ivt_offset = None
    syspage_offset = None
    blocks: list[VerificationBlock] = []

    if kernel is not None:
        symbols = get_symbols(kernel.readelf, str(kernel.elf))
        kernel_start = symbols["init_vectors"]
        ivt_offset = symbols["ivt"] - kernel_start
        syspage_data = symbols.get("syspage_data")
        syspage_offset = syspage_data - kernel_start if syspage_data is not None else None
    elif bin is not None:
        load_addr = bin.load_addr
        ivt_offset = bin.ivt_offset

    if load_addr is None and ivt_offset is not None:
        load_addr = detect_load_address(img_in, ivt_offset)

    if load_addr is None:
        raise RuntimeError("Cannot determine load address automatically.")

    logging.info("Processing image %s", img_in.name)
    if img_in != img_out:
        shutil.copy(img_in, img_out)

    with open(img_out, "r+b") as f:
        image_size = img_out.lstat().st_size
        if syspage_offset is not None and image_size != get_u32_from_file(f, syspage_offset):
            raise RuntimeError("Kernel image size is different from the one stored in syspage")

        image_size = round_up(image_size, IVT_ALIGNMENT)
        # Pad the file to the rounded up size
        f.seek(0, os.SEEK_END)
        file_end = f.tell()
        assert file_end <= image_size
        f.write(PAD_BYTE * (image_size - file_end))

        if ivt_offset is None:
            ivt_offset = image_size
            image_size += 32
            # Reduce max CSF size by 32 bytes - this is so that the small 32-byte IVT header
            # doesn't force the use of a whole extra 4 KB page. The maximum CSF limit is very generous anyway.
            csf_size -= 32 if csf_size != 0 else 0
            f.write(b"\xd1\x00\x20\x41")  # Header - IVT, size 0x20, version 4.1
            f.write(int(load_addr).to_bytes(4, "little"))  # Entrypoint
            f.write(b"\0\0\0\0")  # Reserved
            f.write(b"\0\0\0\0")  # DCD data (NULL)
            f.write(b"\0\0\0\0")  # Boot data (NULL)
            f.write(int(load_addr + ivt_offset).to_bytes(4, "little"))  # self pointer
            csf_pointer = load_addr + image_size if csf_size != 0 else 0
            f.write(csf_pointer.to_bytes(4, "little"))  # CSF pointer
            f.write(b"\0\0\0\0")  # Reserved
        else:
            ivt_self = get_u32_from_file(f, ivt_offset + IvtOffsets.ivt_self)
            boot_data_ptr = get_u32_from_file(f, ivt_offset + IvtOffsets.boot_data)
            if boot_data_ptr != 0:
                boot_data_offset = boot_data_ptr - ivt_self + ivt_offset
                image_size_with_csf = image_size + csf_size
                # Write size of the whole image to boot_data.size
                f.seek(boot_data_offset + BootDataOffsets.size)
                f.write(image_size_with_csf.to_bytes(4, "little"))

            if csf_size != 0:
                f.seek(ivt_offset + IvtOffsets.csf)
                csf_pointer = ivt_self - ivt_offset + image_size
                f.write(csf_pointer.to_bytes(4, "little"))

            if serial_dl:
                # Zero out DCD pointer because it will be written to RAM separately
                dcd_ptr = get_u32_from_file(f, ivt_offset + IvtOffsets.dcd)
                if dcd_ptr != 0:
                    dcd_offset = dcd_ptr - ivt_self + ivt_offset
                    f.seek(ivt_offset + IvtOffsets.dcd)
                    f.write(b"\0\0\0\0")
                    dcd_header = get_u32_from_file(f, dcd_offset, True)
                    dcd_size = (dcd_header >> 8) & 0xFFFF
                    blocks.append(VerificationBlock(DCD_WRITE_ADDR, dcd_offset, dcd_size, img_out))

    blocks.append(VerificationBlock(load_addr, 0, image_size, img_out))
    if sign is not None:
        sign_file(sign, img_out, blocks, csf_size)


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG if args.verbose else logging.INFO)
    kernel = None
    sign = None
    bin = None
    img_in = Path(args.image)
    img_out = img_in
    if args.action in ["sign-kernel", "kernel"]:
        readelf = ("" if args.cross is None else args.cross) + "readelf"
        kernel = KernelArgs(
            readelf,
            args.kernel_elf,
        )

    if args.action in ["sign-kernel", "sign-bin"]:
        sign = SignArgs(args.cst_bin, args.cst_dir, args.sig_max_size, args.temp_dir)
        img_out = img_in.with_suffix(".signed" + img_in.suffix)

    if args.action == "sign-bin":
        bin = BinArgs(args.load_addr, args.ivt_offset)

    process_image(img_in, img_out, args.serial_dl, sign, kernel, bin)
