#!/usr/bin/env python3
#
# Generate LittleFS disk image compatible with Phoenix RTOS driver
#
# Copyright 2024 Phoenix Systems
# Author: Jacek Maksymowicz
#

import argparse
import os
import tarfile
from typing import BinaryIO, Optional, NamedTuple, Tuple
import littlefs
from enum import IntEnum
import logging


class PhoenixAttrs(IntEnum):
    MODE = 0xFB - 5
    GID = 0xFB - 4
    UID = 0xFB - 3
    MTIME = 0xFB - 2
    CTIME = 0xFB - 1
    ATIME = 0xFB - 0
    PHID_REG = 0xFC + 0
    PHID_DIR = 0xFC + 1


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
        blockSize: int,
        blockCount: int,
        idSize: int,
        fakeTimes: bool,
        squashUIDs: bool,
        squashPerms: bool,
        squashTimes: bool,
    ) -> None:
        self.fs = littlefs.LittleFS(block_size=blockSize, block_count=blockCount)
        self.lastPhID = ROOT_PHID
        self.idSize = idSize
        self.useCTime = not fakeTimes
        self.useMTime = not fakeTimes and not squashTimes
        self.useATime = not fakeTimes and not squashTimes
        self.useUIDs = not squashUIDs
        self.squashPerms = squashPerms

    def get_next_phId(self) -> int:
        self.lastPhID += 1
        return self.lastPhID

    def create_root(self, imageRoot: str):
        path = ""
        for nextDir in imageRoot.split("/")[1:]:
            if not nextDir:
                continue

            path += "/" + nextDir
            try:
                self.fs.mkdir(path)
            except littlefs.errors.LittleFSError.Error.LFS_ERR_EXIST:
                continue

            phId = self.get_next_phId()
            mode = S_IFDIR | 0o777
            self.fs.setattr(path, PhoenixAttrs.PHID_DIR, phId.to_bytes(8, "little"))
            self.fs.setattr(path, PhoenixAttrs.MODE, mode.to_bytes(2, "little"))

    def create_file(self, file: Optional[BinaryIO], stat: FileStats, imagePath: str):
        mode = stat.mode
        if self.squashPerms:
            mode = (mode & S_IFMT) | (mode & 0o077)

        logging.info("%s (mode 0x%04x)", imagePath, mode)
        isDir = (mode & S_IFMT) == S_IFDIR
        if isDir:
            self.fs.mkdir(imagePath)
        else:
            with self.fs.open(imagePath, "wb") as fh:
                if file is not None:
                    fh.write(file.read())

        phId = self.get_next_phId()
        phIdType = PhoenixAttrs.PHID_DIR if isDir else PhoenixAttrs.PHID_REG
        self.fs.setattr(imagePath, phIdType, phId.to_bytes(self.idSize, "little"))
        self.fs.setattr(imagePath, PhoenixAttrs.MODE, mode.to_bytes(2, "little"))
        if self.useCTime:
            self.fs.setattr(
                imagePath, PhoenixAttrs.CTIME, stat.ctime.to_bytes(8, "little")
            )

        if self.useMTime:
            self.fs.setattr(
                imagePath, PhoenixAttrs.MTIME, stat.mtime.to_bytes(8, "little")
            )

        if self.useATime:
            self.fs.setattr(
                imagePath, PhoenixAttrs.ATIME, stat.atime.to_bytes(8, "little")
            )

        if self.useUIDs:
            self.fs.setattr(imagePath, PhoenixAttrs.UID, stat.uid.to_bytes(4, "little"))
            self.fs.setattr(imagePath, PhoenixAttrs.GID, stat.gid.to_bytes(4, "little"))

    def dump_contents(self, fh: BinaryIO):
        fh.write(self.fs.context.buffer)

    def traverse(self, sourceRoot: str, imageRoot: str):
        for item in os.listdir(sourceRoot):
            sourcePath = os.path.abspath(os.path.join(sourceRoot, item))
            imagePath = imageRoot + "/" + item
            stat_os = os.stat(sourcePath)
            stat = FileStats(
                mode=stat_os.st_mode,
                ctime=int(stat_os.st_ctime),
                mtime=int(stat_os.st_mtime),
                atime=int(stat_os.st_atime),
                uid=stat_os.st_uid,
                gid=stat_os.st_gid,
            )

            if os.path.isdir(sourcePath):
                self.create_file(None, stat, imagePath)
                self.traverse(sourcePath, imagePath)
            else:
                with open(sourcePath, "rb") as file:
                    self.create_file(file, stat, imagePath)

    def pack_from_fs(self, sourceRoot: str, imageRoot: str):
        self.create_root(imageRoot)
        self.traverse(sourceRoot, imageRoot)

    def pack_from_tar(self, sourcePath: str, imageRoot: str):
        self.create_root(imageRoot)
        tar = tarfile.TarFile(sourcePath, "r")
        while True:
            memb = tar.next()
            if memb is None:
                break

            mode = (memb.mode & ~S_IFMT) | tar_mode(memb)
            stat = FileStats(
                mode=mode,
                ctime=int(memb.mtime),
                mtime=int(memb.mtime),
                atime=int(memb.mtime),
                uid=memb.uid,
                gid=memb.gid,
            )
            path = imageRoot + "/" + memb.name
            self.create_file(tar.extractfile(memb), stat, path)


def split_path(path: str) -> Tuple[str, str]:
    pathSplit = path.split(":")
    sourceRoot = pathSplit[0]
    imageRoot = "" if len(pathSplit) == 1 else pathSplit[1]
    return sourceRoot, imageRoot


def parse_arguments():
    parser = argparse.ArgumentParser(description="")
    source = parser.add_argument_group()

    source.add_argument(
        "-d",
        "--root",
        type=str,
        metavar="directory[:path]",
        help="Copy from a local directory into path (or root)",
    )

    source.add_argument(
        "-a",
        "--tarball",
        type=str,
        metavar="file[:path]",
        help="Copy from a tarfile",
    )

    parser.add_argument(
        "-B",
        "--block-size",
        required=True,
        type=int,
        metavar="bytes",
        help="Block size in bytes",
    )

    parser.add_argument(
        "-i",
        "--id-size",
        required=True,
        type=int,
        metavar="bytes",
        help="Size of id_t on the target platform",
    )

    parser.add_argument(
        "-b",
        "--size-in-blocks",
        required=True,
        type=int,
        metavar="blocks",
        help="Filesystem size in blocks",
    )

    parser.add_argument(
        "-f",
        "--faketime",
        action="store_true",
        help="Don't include timestamps (all timestamps will read as 0)",
    )

    parser.add_argument(
        "-q", "--squash", action="store_true", help='Same as "-U -P -T"'
    )

    parser.add_argument(
        "-U",
        "--squash-uids",
        action="store_true",
        help="Don't include owner UIDs (all files be owned by root)",
    )

    parser.add_argument(
        "-P",
        "--squash-perms",
        action="store_true",
        help="Squash permissions on all files",
    )

    parser.add_argument(
        "-T",
        "--squash-times",
        action="store_true",
        help="Only store creation time of files",
    )

    parser.add_argument(
        "-V", "--version", action="store_true", help="Display version information"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "output", type=argparse.FileType("wb"), help="Output image file"
    )

    args = parser.parse_args()
    if args.squash:
        args.squash_uids = True
        args.squash_perms = True
        args.squash_times = True

    if args.root is None and args.tarball is None:
        raise ValueError("At least one source must be given")

    return args


if __name__ == "__main__":
    args = parse_arguments()
    if args.version:
        print("GenLittleFS version 1.0")
        exit(0)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARN)

    c = PhLFSCreator(
        args.block_size,
        args.size_in_blocks,
        args.id_size,
        args.faketime,
        args.squash_uids,
        args.squash_perms,
        args.squash_times,
    )

    if args.root is not None:
        c.pack_from_fs(*split_path(args.root))

    if args.tarball is not None:
        c.pack_from_tar(*split_path(args.tarball))

    c.dump_contents(args.output)
    args.output.close()
