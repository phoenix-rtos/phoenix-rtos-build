#
# Common fixtures for image_builder/nvm_config/strip tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
import random
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import image_builder as ib  # noqa: E402
from elfgen import KERNEL_SEGMENTS, make_elf32  # noqa: E402

TARGET = "armv7a7-imx6ull-evk"
KERNEL = "phoenix-armv7a7-imx6ull"
SIZE_PAGE = 0x1000


@dataclass
class BuildTree:
    """Fake build directories, exported to image_builder via env like build.sh does"""
    root: Path

    @property
    def boot(self) -> Path:
        return self.root / "boot"

    @property
    def rootfs(self) -> Path:
        return self.root / "rootfs"

    @property
    def prog(self) -> Path:
        return self.root / "prog.stripped"

    @property
    def plo(self) -> Path:
        return self.root / "plo-scripts"

    def write(self, name: str, text: str) -> Path:
        """Write (dedented) text file relative to the tree root"""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))
        return path

    def payload(self, name: str, size: int, directory: Path | None = None) -> Path:
        """Deterministic non-zero content, so that misplaced data or padding is visible"""
        path = (directory or self.prog) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(random.Random(name).randbytes(size).replace(b"\0", b"\1"))
        return path

    def kernel(self, bin_size: int = 0x16e18) -> Path:
        """Stripped kernel ELF (program headers only) + its binary image"""
        make_elf32(self.prog / f"{KERNEL}.elf", KERNEL_SEGMENTS)
        return self.payload(f"{KERNEL}.bin", bin_size)


@pytest.fixture(autouse=True)
def tree(tmp_path, monkeypatch) -> BuildTree:
    t = BuildTree(tmp_path)
    for d in (t.boot, t.rootfs, t.prog):
        d.mkdir()

    env = {
        "TARGET": TARGET,
        "SIZE_PAGE": str(SIZE_PAGE),
        "PREFIX_BOOT": str(t.boot),
        "PREFIX_ROOTFS": str(t.rootfs),
        "PREFIX_PROG_STRIPPED": str(t.prog),
        "PLO_SCRIPT_DIR": str(t.plo),
        "BOOT_DEVICE": "flash0",
        "MAGIC_USER_SCRIPT": "dabaabad",
    }
    monkeypatch.delenv("RAM_SCRIPT", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    # module globals are normally set by parse_args() - set them for direct calls, restore after the test
    for name, val in (("TARGET", TARGET), ("SIZE_PAGE", SIZE_PAGE), ("PREFIX_BOOT", t.boot),
                      ("PREFIX_ROOTFS", t.rootfs), ("PREFIX_PROG_STRIPPED", t.prog), ("PLO_SCRIPT_DIR", t.plo)):
        monkeypatch.setattr(ib, name, val, raising=False)
    monkeypatch.setattr(logging, "verbose", lambda *args, **kwargs: None, raising=False)
    root = logging.getLogger()
    monkeypatch.setattr(root, "level", root.level)

    monkeypatch.chdir(tmp_path)
    return t


@pytest.fixture
def run_ib(monkeypatch):
    """Run image_builder CLI in-process (coverage, exceptions visible to pytest.raises)"""
    def run(*argv: str) -> int:
        monkeypatch.setattr(sys, "argv", ["image_builder.py", *argv])
        return ib.main()

    return run


@pytest.fixture
def psdisk(monkeypatch):
    """Replaces psdisk call: records argv and writes a fake partition table"""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[1]).write_bytes(b"PTABLE" + bytes(range(26)))
        return ib.subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(ib.subprocess, "run", fake_run)
    return calls
