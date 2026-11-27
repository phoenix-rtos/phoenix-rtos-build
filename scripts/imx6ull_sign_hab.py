#!/usr/bin/env python3
#
# Script for signing kernel or raw binary images using IMX CST tool
#
# Copyright 2026 Phoenix Systems
# Author: Jacek Maksymowicz
#

import argparse
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Iterable, List, NamedTuple, Optional
from pathlib import Path
from imx_hab_defs import ImxIvt, ImxBootData
from image_builder import get_elf_symbols

# 8 KB should be enough even for 4096-bit RSA signatures
CSF_MAX_SIZE = 8192
DCD_WRITE_ADDR = 0x00910000
DEFAULT_IMAGE_NAME = "phoenix-kernel.img"
PAD_BYTE = b"\0"


def parse_args():
    def add_sign_arguments(parser: argparse.ArgumentParser):
        parser.add_argument("--cst-bin", help="Path to CST tool binary", type=Path, required=True)
        parser.add_argument(
            "--cst-template",
            help="Path to CST template file. Paths in the template file will be relative to its parent directory.",
            type=Path,
            required=True,
        )
        parser.add_argument(
            "--sig-max-size", help="Maximum size of signature (CSF)", type=lambda x: int(x, 0), default=CSF_MAX_SIZE
        )

    prefix_boot = os.environ.get("PREFIX_BOOT")
    default_image = Path(prefix_boot) / DEFAULT_IMAGE_NAME if prefix_boot is not None else None
    fc = argparse.ArgumentDefaultsHelpFormatter

    parser = argparse.ArgumentParser("imx6ull secure boot image generator", formatter_class=fc)
    parser.add_argument("--temp-dir", default=os.environ.get("PREFIX_BUILD"), help="Temporary directory path")
    parser.add_argument(
        "--image", help="Image to modify", type=Path, default=default_image, required=(default_image is None)
    )
    parser.add_argument("--sdp-upload", help="Create image for serial download", action="store_true")
    parser.add_argument("--verbose", help="Verbose logging", action="store_true")

    subparsers = parser.add_subparsers(dest="action", required=True)

    sk_parser = subparsers.add_parser("sign-kernel", help="Finalize and sign kernel image", formatter_class=fc)
    add_sign_arguments(sk_parser)
    sk_parser.add_argument("--kernel-elf", help="Kernel .elf file", type=Path, required=True)

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


def round_up(x: int, factor: int):
    return ((x + factor - 1) // factor) * factor


def quote_path(p: Path):
    quote_trans = str.maketrans({'"': '\\"'})
    return '"' + p.absolute().as_posix().translate(quote_trans) + '"'


class SignArgs(NamedTuple):
    cst_bin: Path
    cst_template: Path
    max_size: int
    temp_dir: Optional[Path]


class KernelArgs(NamedTuple):
    elf: Path


class BinArgs(NamedTuple):
    load_addr: int
    ivt_offset: Optional[int]


class VerificationBlock(NamedTuple):
    load_addr: int
    file_offset: int
    size: int
    file: Path


def insert_into_config(str_in: str, new: str) -> str:
    """
    This function will insert the given string at the end of the first `[Authenticate Data]` section
    in the given string.

    CST templates are *almost* parse'able with default Python module `configparser`,
    but because they can contain duplicate sections (in particular multiple `[Authenticate Data]` sections)
    we need to parse them by hand.
    """
    match = re.search(r"\s*\[Authenticate Data\]\s*", str_in, re.IGNORECASE)
    if not match:
        raise KeyError("Authenticate Data section not found")

    section_start = match.end(0)
    match = re.search(r"\s*\[[^]]*\]\s*", str_in[section_start:], re.IGNORECASE)
    section_length = len(str_in[section_start:]) if not match else match.start(0)
    section_end = section_start + section_length
    section_slice = str_in[section_start:section_end]
    if re.search(r"^\s*blocks\s*[=:]", section_slice, re.IGNORECASE | re.MULTILINE):
        # In this case CST tool would silently ignore the second "blocks" attribute
        raise RuntimeError("CST template already has defined blocks")

    out = str_in[:section_end] + "\n" + new + "\n" + str_in[section_end:]
    return out


# This is only necessary because Python versions before 3.12 don't support `delete_on_close` argument
# for `tempfile.NamedTemporaryFile`. If we drop support for < 3.12, we can remove this wrapper class.
class TempFileWrapper:
    def __init__(self, *args, **kwargs) -> None:
        self.file = tempfile.NamedTemporaryFile("w", delete=False, *args, **kwargs)

    def __enter__(self):
        return self.file

    def __exit__(self, exc_type, exc, tb):
        self.file.close()
        try:
            os.unlink(self.file.name)
        except OSError:
            pass


def sign_file(sign: SignArgs, img_out: Path, blocks: Iterable[VerificationBlock], csf_size: int):
    logging.info("Signing image %s", img_out.name)
    if not sign.cst_template.is_file():
        raise FileNotFoundError(str(sign.cst_template))

    blocks_str = "Blocks = " + ", ".join(
        f"0x{x.load_addr:08x} 0x{x.file_offset:08x} 0x{x.size:08x} {quote_path(x.file)}" for x in blocks
    )
    filled_config = insert_into_config(sign.cst_template.read_text(), blocks_str)

    with (
        TempFileWrapper(suffix=".cst", dir=sign.temp_dir) as filled_cst,
        TempFileWrapper(suffix=".bin", dir=sign.temp_dir) as sig_file,
    ):
        logging.debug("Filled CST in %s, signature in %s", filled_cst.name, sig_file.name)
        filled_cst.write(filled_config)
        filled_cst.close()
        sig_file.close()
        sig_file_path = Path(sig_file.name).absolute()
        filled_cst_path = Path(filled_cst.name).absolute()
        cmd_result = subprocess.run(
            [sign.cst_bin, "--o", sig_file_path, "--i", filled_cst_path],
            cwd=sign.cst_template.parent,
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
        raise RuntimeError("Returned signature has size 0")

    pad_size = csf_size - sig_size
    with open(img_out, "ab") as f:
        f.write(sig_bin)
        # Not sure why, but padding to maximum reserved size seems to be necessary for Flash boot.
        # Perhaps reading from uninitialized Flash causes a failure?
        f.write(PAD_BYTE * pad_size)


def detect_load_address(image: Path, ivt_offset: int):
    with open(image, "rb") as f:
        f.seek(ivt_offset)
        ivt = ImxIvt.unpack(f.read(ImxIvt.SIZE))
        if ivt.boot_data == 0:
            return None

        f.seek(ivt.calculate_offset(ivt.boot_data, ivt_offset))
        boot_data = ImxBootData.unpack(f.read(ImxBootData.SIZE))
        return boot_data.load_addr


def process_image(
    img_in: Path,
    img_out: Path,
    sdp_upload: bool,
    sign: Optional[SignArgs],
    kernel: Optional[KernelArgs],
    bin: Optional[BinArgs],
):
    csf_size = sign.max_size if sign is not None else 0

    load_addr = None
    ivt_offset = None
    dcd_offset = None
    blocks: List[VerificationBlock] = []

    if kernel is not None:
        symbols = get_elf_symbols(
            kernel.elf,
            set(
                (
                    "init_vectors",
                    "ivt",
                    "dcd",
                )
            ),
        )
        kernel_start = symbols["init_vectors"]
        ivt_offset = symbols["ivt"] - kernel_start
        dcd_offset = symbols["dcd"] - kernel_start
    elif bin is not None:
        load_addr = bin.load_addr
        ivt_offset = bin.ivt_offset

    if load_addr is None and ivt_offset is not None:
        load_addr = detect_load_address(img_in, ivt_offset)

    if load_addr is None:
        raise RuntimeError("Cannot determine load address automatically.")

    logging.info("Processing image %s%s", img_in.name, " for serial download" if sdp_upload else "")
    if img_in != img_out:
        shutil.copy(img_in, img_out)

    with open(img_out, "r+b") as f:
        f.seek(0, os.SEEK_END)
        file_end = f.tell()
        # Pad the file to the rounded up size
        image_size = round_up(file_end, ImxIvt.SIZE)
        f.write(PAD_BYTE * (image_size - file_end))

        if ivt_offset is None:
            ivt_offset = image_size
            image_size += 32
            # Reduce max CSF size by 32 bytes - this is so that the small 32-byte IVT header
            # doesn't force the use of a whole extra 4 KB page. The maximum CSF limit is very generous anyway.
            csf_size -= 32 if csf_size != 0 else 0
            csf_pointer = load_addr + image_size if csf_size != 0 else 0
            ivt = ImxIvt(entry=load_addr, ivt_self=load_addr + ivt_offset, csf=csf_pointer)
        else:
            f.seek(ivt_offset)
            ivt = ImxIvt.unpack(f.read(ImxIvt.SIZE))

        if csf_size != 0:
            ivt.csf = ivt.ivt_self - ivt_offset + image_size

        if sdp_upload:
            # Note: we can't always take DCD offset from the IVT, as it probably has been
            # zeroed out before calling this script
            if dcd_offset is None and ivt.dcd != 0:
                dcd_offset = ivt.dcd

            ivt.dcd = 0
            if dcd_offset is not None:
                f.seek(dcd_offset)
                dcd_header = struct.unpack(">I", f.read(4))[0]  # Headers are big-endian
                dcd_size = (dcd_header >> 8) & 0xFFFF
                blocks.append(VerificationBlock(DCD_WRITE_ADDR, dcd_offset, dcd_size, img_out))

        if ivt.boot_data != 0:
            boot_data_offset = ivt.calculate_offset(ivt.boot_data, ivt_offset)
            f.seek(boot_data_offset)
            boot_data = ImxBootData.unpack(f.read(ImxBootData.SIZE))
            # Write size of the whole image to boot_data.size
            boot_data.load_size = image_size + csf_size
            f.seek(boot_data_offset)
            f.write(boot_data.pack())

        f.seek(ivt_offset)
        f.write(ivt.pack())

    blocks.append(VerificationBlock(load_addr, 0, image_size, img_out))
    if sign is not None:
        sign_file(sign, img_out, blocks, csf_size)


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG if args.verbose else logging.INFO)
    kernel = None
    bin = None
    img_in = Path(args.image)
    img_out = img_in
    if args.action == "sign-kernel":
        kernel = KernelArgs(args.kernel_elf)
    elif args.action == "sign-bin":
        bin = BinArgs(args.load_addr, args.ivt_offset)

    sign = SignArgs(args.cst_bin, args.cst_template, args.sig_max_size, args.temp_dir)
    img_out = img_in.with_suffix(".signed" + img_in.suffix)

    process_image(img_in, img_out, args.sdp_upload, sign, kernel, bin)
