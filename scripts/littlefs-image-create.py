#!/usr/bin/env python3
#
# Generate LittleFS disk image compatible with Phoenix RTOS driver
#
# Copyright 2024 Phoenix Systems
# Author: Jacek Maksymowicz
#

import argparse
import tarfile
import time
from typing import IO, BinaryIO, Optional, NamedTuple, Tuple, cast
import littlefs
from enum import IntEnum
import logging
from pathlib import Path, PurePosixPath


VERSION = (1, 0, 0)


class LfsPath(PurePosixPath):
    pass


class PhoenixAttrs(IntEnum):
    MODE = 0xFC - 6
    GID = 0xFC - 5
    UID = 0xFC - 4
    MTIME = 0xFC - 3
    CTIME = 0xFC - 2
    ATIME = 0xFC - 1
    PHID_REG = 0xFC + 0
    PHID_DIR = 0xFC + 1


PHOENIX_ATTRS_SIZES = {
    PhoenixAttrs.MODE: 4,
    PhoenixAttrs.GID: 4,
    PhoenixAttrs.UID: 4,
    PhoenixAttrs.MTIME: 8,
    PhoenixAttrs.CTIME: 8,
    PhoenixAttrs.ATIME: 8,
}

ROOT_PHID = 1
S_IFMT = 0xF000
S_IFLNK = 0xA000
S_IFREG = 0x8000
S_IFBLK = 0x6000
S_IFDIR = 0x4000
S_IFCHR = 0x2000
S_IFIFO = 0x1000


def tar_mode(memb: tarfile.TarInfo) -> int:
    if memb.islnk():
        return S_IFLNK
    elif memb.isblk():
        return S_IFBLK
    elif memb.isdir():
        return S_IFDIR
    elif memb.ischr():
        return S_IFCHR
    elif memb.isfifo():
        return S_IFIFO
    else:
        return S_IFREG


class FileStats(NamedTuple):
    mode: int
    ctime: int
    mtime: int
    atime: int
    uid: int
    gid: int


class PhLFSCreator:
    def __init__(
        self,
        block_size: int,
        fs_size: int,
        id_size: int,
        fake_times: bool,
        no_uids: bool,
        no_perms: bool,
        squash_times: bool,
    ) -> None:
        assert fs_size != 0
        assert id_size != 0

        if fs_size % block_size != 0:
            logging.warning(
                "FS size (0x%x) is not multiple of block size (0x%x). Rounding down to block size.", fs_size, block_size
            )

        block_count = fs_size // block_size
        if block_count < 2:
            raise ValueError("Partition smaller than 2 blocks. Cannot create filesystem.")

        self.fs = littlefs.LittleFS(block_size=block_size, block_count=block_count)
        self.last_phID = ROOT_PHID
        self.id_size = id_size
        self.use_ctime = not fake_times
        self.use_mtime = not fake_times and not squash_times
        self.use_atime = not fake_times and not squash_times
        self.use_uids = not no_uids
        self.no_perms = no_perms

    def get_next_phId(self) -> int:
        self.last_phID += 1
        return self.last_phID

    def set_attr_on_file(self, path: LfsPath, type: PhoenixAttrs, attr: int):
        if type in PHOENIX_ATTRS_SIZES:
            size = PHOENIX_ATTRS_SIZES[type]
        elif type == PhoenixAttrs.PHID_REG or type == PhoenixAttrs.PHID_DIR:
            size = self.id_size
        else:
            raise KeyError(type)

        serialized = attr.to_bytes(size, "little")
        self.fs.setattr(str(path), type, serialized)

    def create_root(self, image_root: LfsPath):
        for dir in [*image_root.parents, image_root]:
            # Note: `makedirs` can create all preceding directories, but we need to set Phoenix ID
            # and other attributes along the way - so we need to do each directory manually
            try:
                self.fs.mkdir(str(dir))
            except FileExistsError:
                continue

            logging.info("Creating dir %s", dir)
            phId = self.get_next_phId()
            self.set_attr_on_file(dir, PhoenixAttrs.PHID_DIR, phId)
            mode = S_IFDIR | (0o777 if self.no_perms else 0o755)
            self.set_attr_on_file(dir, PhoenixAttrs.MODE, mode)
            if self.use_ctime:
                self.set_attr_on_file(dir, PhoenixAttrs.CTIME, int(time.time()))

    def create_file(self, file: Optional[IO[bytes]], stat: FileStats, image_path: LfsPath):
        mode = stat.mode
        if self.no_perms:
            mode = (mode & S_IFMT) | 0o777

        logging.info("Packing %s (mode 0x%04x)", image_path, mode)
        is_dir = (mode & S_IFMT) == S_IFDIR
        existed = False
        if is_dir:
            try:
                self.fs.mkdir(str(image_path))
            except FileExistsError:
                return
        else:
            try:
                f_img = self.fs.open(str(image_path), "xb")
            except FileExistsError:
                existed = True
                logging.warning("File already exists: %s. Overwriting contents.", image_path)
                f_img = self.fs.open(str(image_path), "wb")

            if file is not None:
                while True:
                    chunk = file.read(self.fs.cfg.block_size)
                    if not chunk:
                        break

                    f_img.write(chunk)

            f_img.close()

        if not existed:
            phIdType = PhoenixAttrs.PHID_DIR if is_dir else PhoenixAttrs.PHID_REG
            phId = self.get_next_phId()
            self.set_attr_on_file(image_path, phIdType, phId)

        self.set_attr_on_file(image_path, PhoenixAttrs.MODE, mode)
        if self.use_ctime:
            self.set_attr_on_file(image_path, PhoenixAttrs.CTIME, stat.ctime)

        if self.use_mtime:
            self.set_attr_on_file(image_path, PhoenixAttrs.MTIME, stat.mtime)

        if self.use_atime:
            self.set_attr_on_file(image_path, PhoenixAttrs.ATIME, stat.atime)

        if self.use_uids:
            self.set_attr_on_file(image_path, PhoenixAttrs.UID, stat.uid)
            self.set_attr_on_file(image_path, PhoenixAttrs.GID, stat.gid)

    def verify_phID_presence(self):
        """
        Verify that every file in the filesystem contains a Phoenix ID of appropriate type.
        Intended for debugging this script - errors should never happen in correctly working script.
        """
        for dir_name, dirs, files in self.fs.walk("/"):
            for file in files:
                path = str(LfsPath(dir_name) / file)
                self.fs.getattr(path, PhoenixAttrs.PHID_REG)
                try:
                    self.fs.getattr(path, PhoenixAttrs.PHID_DIR)
                    raise RuntimeError(f"{path} contains invalid type of Phoenix ID")
                except littlefs.LittleFSError:
                    pass

            for dir in dirs:
                path = str(LfsPath(dir_name) / dir)
                self.fs.getattr(path, PhoenixAttrs.PHID_DIR)
                try:
                    self.fs.getattr(path, PhoenixAttrs.PHID_REG)
                    raise RuntimeError(f"{path} contains invalid type of Phoenix ID")
                except littlefs.LittleFSError:
                    pass

    def dump_contents(self, fh: BinaryIO):
        fh.write(self.fs.context.buffer)

    def pack_from_file(self, item: Path, image_path: LfsPath):
        stat_os = item.stat()
        stat = FileStats(
            mode=stat_os.st_mode,
            ctime=int(stat_os.st_ctime),
            mtime=int(stat_os.st_mtime),
            atime=int(stat_os.st_atime),
            uid=stat_os.st_uid,
            gid=stat_os.st_gid,
        )

        if item.is_dir():
            self.create_file(None, stat, image_path)
            self.traverse_fs(item, image_path)
        else:
            with open(item, "rb") as file:
                self.create_file(file, stat, image_path)

    def traverse_fs(self, sourceRoot: Path, image_root: LfsPath):
        if sourceRoot.is_dir():
            for item in sourceRoot.iterdir():
                self.pack_from_file(item, image_root / item.name)
        else:
            self.pack_from_file(sourceRoot, image_root / sourceRoot.name)

    def pack_from_fs(self, sourceRoot: Path, image_root: LfsPath):
        self.create_root(image_root)
        self.traverse_fs(sourceRoot, image_root)

    def pack_from_tar(self, source_path: Path, image_root: LfsPath):
        self.create_root(image_root)
        with tarfile.TarFile(source_path, "r") as tar:
            for file in tar:
                mode = (file.mode & ~S_IFMT) | tar_mode(file)
                stat = FileStats(
                    mode=mode,
                    ctime=int(file.mtime),
                    mtime=int(file.mtime),
                    atime=int(file.mtime),
                    uid=file.uid,
                    gid=file.gid,
                )
                path = image_root / file.name
                self.create_file(tar.extractfile(file), stat, path)


def split_path(path: str) -> Tuple[Path, LfsPath]:
    pathSplit = path.rsplit(":", 1)
    sourceRoot = Path(pathSplit[0]).absolute()
    image_root = LfsPath("/") / ("" if len(pathSplit) == 1 else pathSplit[1])
    if not sourceRoot.exists():
        raise FileNotFoundError(sourceRoot)

    return sourceRoot, image_root


def parse_arguments():
    parser = argparse.ArgumentParser(description="Create LittleFS file system image for use with Phoenix-RTOS.")
    source = parser.add_argument_group()

    parser.add_argument("-o", "--output", required=True, type=argparse.FileType("wb"), help="Output image file")

    parser.add_argument(
        "-s",
        "--fs-size",
        required=True,
        type=lambda x: int(x, 0),
        metavar="bytes",
        help="Filesystem size in bytes",
    )

    parser.add_argument(
        "-b",
        "--block-size",
        required=True,
        type=lambda x: int(x, 0),
        metavar="bytes",
        help="Size of erase block in bytes",
    )

    parser.add_argument(
        "-i", "--id-size", required=True, type=int, metavar="bytes", help="Size of id_t on the target platform"
    )

    parser.add_argument(
        "-t", "--no-times", action="store_true", help="Don't include timestamps (all timestamps will read as 0)"
    )

    parser.add_argument("-S", "--squash", action="store_true", help='Same as "-U -P -T"')

    parser.add_argument(
        "-U", "--no-uids", action="store_true", help="Don't include owner UIDs (all files be owned by root)"
    )

    parser.add_argument("-P", "--no-perms", action="store_true", help="Set permissions to `rwxrwxrwx` on all files")

    parser.add_argument("-T", "--squash-times", action="store_true", help="Only store creation time of files")

    parser.add_argument(
        "-V", "--version", action="version", version=f"{parser.prog} {VERSION[0]}.{VERSION[1]}.{VERSION[2]}"
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    source.add_argument(
        "--tar",
        action="append",
        default=[],
        type=split_path,
        metavar="tar_path[:img_path]",
        help="Copy from a tarfile `tar_path` into directory `img_path` in the image (or root)",
    )

    source.add_argument(
        "paths",
        nargs="*",
        default=[],
        type=split_path,
        metavar="src_path[:img_path]",
        help="Copy from a local file/directory `src_path` into directory `img_path` in the image (or root)",
    )

    args = parser.parse_args()
    if args.squash:
        args.no_uids = True
        args.no_perms = True
        args.squash_times = True

    return args


if __name__ == "__main__":
    args = parse_arguments()
    try:
        logging.basicConfig(level=logging.INFO if args.verbose else logging.WARN)
        c = PhLFSCreator(
            args.block_size,
            args.fs_size,
            args.id_size,
            args.no_times,
            args.no_uids,
            args.no_perms,
            args.squash_times,
        )

        for source_path, image_path in args.tar:
            source_path = cast(Path, source_path)
            c.pack_from_tar(source_path, image_path)

        for source_path, image_path in args.paths:
            source_path = cast(Path, source_path)
            c.pack_from_fs(source_path, image_path)

        c.dump_contents(args.output)
    finally:
        args.output.close()
