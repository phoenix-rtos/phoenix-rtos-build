#
# image_builder.py command line (functional) tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import KERNEL

IMAGE_BUILDER = Path(__file__).resolve().parents[1] / "image_builder.py"

NVM = """
    flash0:
      size: 0x1000000
      block_size: 0x10000
      padding_byte: 0xff
      partitions:
        - name: plo
          size: 0x10000
        - name: kernel
          size: 0x100000
        - name: rootfs
          type: jffs2
    """

# zynq7000-like: absolute preinit script (built into plo) calling relative user script from `kernel` partition
PREINIT = """
    size: 0x1000
    is_relative: False
    contents:
      - map ddr 0x100000 0x1ffffff rwx
      - phfs {{ env.BOOT_DEVICE }} 2.0 raw
      - console 0.0
      - if: '{{ not(env.RAM_SCRIPT) | default(false) }}'
        action: call
        set_base: True
        device: '{{ env.BOOT_DEVICE }}'
        filename: user.plo
        offset: '{{ nvm.flash0.kernel.offs }}'
        target_magic: '{{ env.MAGIC_USER_SCRIPT }}'
    """

USER = """
    magic: '{{ env.MAGIC_USER_SCRIPT }}'
    size: 0x1000
    is_relative: True
    contents:
      - wait 500
      - kernel {{ env.BOOT_DEVICE }}
      - app {{ env.BOOT_DEVICE }} -x dummyfs;-N;devfs;-D ddr ddr
      - action: app
        device: '{{ env.BOOT_DEVICE }}'
        flags: EXEC
        filename: psh
        args: '-i;/etc/rc.psh;{{ "-v" if env.PSH_VERBOSE is defined else "" }}'
        text_map: ddr
        data_maps: ddr
      - blob {{ env.BOOT_DEVICE }} /etc/hostid ddr
      - go!
    """


@pytest.fixture
def project(tree):
    """Sample project: NVM config, plo scripts and all binaries they reference"""
    tree.write("nvm.yaml", NVM)
    tree.write("preinit.plo.yaml", PREINIT)
    tree.write("user.plo.yaml", USER)
    tree.kernel()
    tree.payload("dummyfs", 0x976c)
    tree.payload("psh", 0x3210)
    tree.payload("etc/hostid", 4, tree.rootfs)
    return tree


def kernel_elf_size(tree):
    return (tree.prog / f"{KERNEL}.elf").stat().st_size


def test_query(project, run_ib, capsys):
    assert run_ib("query", "{{ nvm.flash0.rootfs.offs }} {{ nvm.flash0._meta.block_size }} {{ env.BOOT_DEVICE }}") == 0
    assert capsys.readouterr().out == "1114112 65536 flash0\n"


def test_query_without_nvm(tree, run_ib, capsys):
    assert run_ib("query", "--nvm", "", "{{ 1 + 1 }}") == 0
    assert capsys.readouterr().out == "2\n"


def test_script_preinit(project, run_ib, monkeypatch):
    assert run_ib("script", "--script", "preinit.plo.yaml", "--out", "script.plo") == 0
    monkeypatch.setenv("RAM_SCRIPT", "1")
    assert run_ib("script", "--script", "preinit.plo.yaml", "--out", "script-ram.plo") == 0

    common = "map ddr 0x100000 0x1ffffff rwx\nphfs flash0 2.0 raw\nconsole 0.0\n"
    assert (project.plo / "script.plo").read_text() == common + (
        "alias -b 0x10000\n"
        "alias user.plo 0x10000 0x1000\n"
        "call flash0 user.plo dabaabad\n"
        "\0")
    assert (project.plo / "script-ram.plo").read_text() == common + "\0"


def test_script_user(project, run_ib):
    assert run_ib("script", "--script", "user.plo.yaml") == 0

    assert (project.plo / "user.plo").read_text() == (
        "dabaabad\n"
        "wait 500\n"
        f"alias -r {KERNEL}.elf 0x1000 {kernel_elf_size(project):#x}\n"
        "kernel flash0\n"
        "alias -r dummyfs 0x2000 0x976c\n"
        "app flash0 -x dummyfs;-N;devfs;-D ddr ddr\n"
        "alias -r psh 0xc000 0x3210\n"
        "app flash0 -x psh;-i;/etc/rc.psh ddr ddr\n"
        "alias -r hostid 0x10000 0x4\n"
        "blob flash0 hostid ddr\n"
        "go!\n"
        "\0")


def test_script_out_paths(project, run_ib):
    assert run_ib("script", "--script", "user.plo.yaml", "--out", "custom.plo") == 0
    assert run_ib("script", "--script", "user.plo.yaml", "--out", str(project.boot / "abs.plo")) == 0

    assert (project.plo / "custom.plo").read_text() == (project.boot / "abs.plo").read_text()


def test_script_error(project, run_ib):
    project.write("bad.plo.yaml", """
        size: 0x1000
        contents:
          - kernel {{ env.KERNEL_DEVICE }}
        """)

    with pytest.raises(ValueError, match="Failed to parse PLO CMD"):
        run_ib("script", "--script", "bad.plo.yaml")


def test_partition_relative_script(project, run_ib):
    assert run_ib("-v", "partition", "--name", "kernel", "--script", "user.plo.yaml") == 0

    img = (project.boot / "part_kernel.img").read_bytes()
    script = (project.plo / "user.plo").read_bytes()
    kernel = (project.prog / f"{KERNEL}.elf").read_bytes()
    expected = [(0, script), (0x1000, kernel), (0x2000, (project.prog / "dummyfs").read_bytes()),
                (0xc000, (project.prog / "psh").read_bytes()), (0x10000, (project.rootfs / "etc/hostid").read_bytes())]
    assert len(img) == 0x10004
    for offs, data in expected:
        assert img[offs:offs + len(data)] == data
    assert img[len(script):0x1000] == b"\xff" * (0x1000 - len(script))
    assert img[0x1000 + len(kernel):0x2000] == b"\xff" * (0x1000 - len(kernel))


def test_partition_absolute_script(project, run_ib):
    project.write("abs.plo.yaml", """
        size: 0x1000
        offs: '{{ nvm.flash0.kernel.offs }}'
        contents:
          - kernelimg {{ env.BOOT_DEVICE }}
          - app {{ env.BOOT_DEVICE }} -x psh ddr ddr
        """)

    assert run_ib("partition", "--name", "flash0:kernel", "--script", "abs.plo.yaml") == 0

    # aliases are absolute (flash offsets), partition image offsets are relative to the partition start
    assert (project.plo / "abs.plo").read_text() == (
        f"alias {KERNEL}.bin 0x11000 0x16e18\n"
        f"kernelimg flash0 {KERNEL}.bin 0xc0000000 0x17000 0xc0018000 0x19000\n"
        "alias psh 0x28000 0x3210\n"
        "app flash0 -x psh ddr ddr\n"
        "\0")
    img = (project.boot / "part_kernel.img").read_bytes()
    assert img[0x1000:0x1000 + 0x16e18] == (project.prog / f"{KERNEL}.bin").read_bytes()
    assert img[0x18000:] == (project.prog / "psh").read_bytes()


def test_partition_too_large(project, run_ib):
    project.payload("psh", 0x100000)

    with pytest.raises(AssertionError, match="exceeds total size"):
        run_ib("partition", "--name", "kernel", "--script", "user.plo.yaml")


def test_partition_unknown(project, run_ib):
    with pytest.raises(ValueError, match="Can't find target partition"):
        run_ib("partition", "--name", "flash1:kernel", "--script", "user.plo.yaml")


def test_partition_contents(project, run_ib):
    plo = project.payload("plo.img", 0x1234)
    extra = project.payload("extra.img", 0x10)

    assert run_ib("part", "--name", "plo", "--contents", str(plo), "--contents", f"{extra}:8192") == 0

    assert (project.boot / "part_plo.img").read_bytes() == plo.read_bytes() + b"\xff" * 0xdcc + extra.read_bytes()


def test_partition_contents_appended(project, run_ib):
    a, b = project.payload("a.img", 0x10), project.payload("b.img", 0x10)

    assert run_ib("part", "--name", "plo", "--contents", str(a), "--contents", str(b)) == 0

    assert (project.boot / "part_plo.img").read_bytes() == a.read_bytes() + b.read_bytes()


@pytest.mark.xfail(strict=True, reason="--contents offset is parsed as decimal only")
def test_partition_contents_hex_offset(project, run_ib):
    plo = project.payload("plo.img", 0x10)

    assert run_ib("part", "--name", "plo", "--contents", f"{plo}:0x1000") == 0


def test_disk(project, run_ib):
    run_ib("partition", "--name", "plo", "--contents", str(project.payload("plo.img", 0x800)))
    run_ib("partition", "--name", "kernel", "--script", "user.plo.yaml")
    rootfs = project.payload("rootfs.jffs2", 0x3000, project.boot)

    assert run_ib("disk", "--part", "rootfs=rootfs.jffs2") == 0

    disk = (project.boot / "flash0.disk").read_bytes()
    kernel = (project.boot / "part_kernel.img").read_bytes()
    assert len(disk) == 0x110000 + 0x3000
    assert disk[:0x800] == (project.boot / "part_plo.img").read_bytes()
    assert disk[0x800:0x10000] == b"\xff" * (0x10000 - 0x800)
    assert disk[0x10000:0x10000 + len(kernel)] == kernel
    assert disk[0x110000:] == rootfs.read_bytes()


def test_disk_overrides(project, run_ib, tmp_path):
    plo = project.payload("plo.img", 0x10, tmp_path / "elsewhere")
    project.payload("part_kernel.img", 0x20, project.boot)

    assert run_ib("disk", "--part", f"flash0:plo={plo}", "--part", "rootfs=none", "--out", "custom.disk") == 0

    disk = (project.boot / "custom.disk").read_bytes()
    assert disk == plo.read_bytes() + b"\xff" * 0xfff0 + (project.boot / "part_kernel.img").read_bytes()


def test_disk_empty_and_virtual(tree, run_ib):
    tree.write("nvm.yaml", """
        hd0:
          size: 0x10000
          block_size: 0x1000
          partitions:
            - {name: plo, size: 0x1000}
            - {name: mbr, offs: 0x1be, size: 0x10, virtual: True}
            - {name: extra, offs: 0x2000, size: 0x1000, virtual: True}
            - {name: data, offs: 0x4000, empty: True}
        """)
    plo = tree.payload("part_plo.img", 0x200, tree.boot)
    mbr = tree.payload("part_hd0_mbr.img", 0x10, tree.boot)

    assert run_ib("disk", "--out", str(tree.root / "hd0.img")) == 0

    # virtual partition (ia32 MBR) overwrites the reserved space in plo, missing virtual and empty ones are skipped
    plo_data = plo.read_bytes()
    assert (tree.root / "hd0.img").read_bytes() == plo_data[:0x1be] + mbr.read_bytes() + plo_data[0x1ce:]


def test_disk_select_flash(tree, run_ib):
    tree.write("nvm.yaml", """
        flash0:
          size: 0x10000
          block_size: 0x1000
          partitions: [{name: a}]
        flash1:
          size: 0x10000
          block_size: 0x1000
          partitions: [{name: b}]
        """)
    tree.payload("part_b.img", 0x10, tree.boot)

    assert run_ib("disk", "--name", "flash1") == 0
    assert (tree.boot / "flash1.disk").exists() and not (tree.boot / "flash0.disk").exists()

    with pytest.raises(ValueError, match="No disk image created"):
        run_ib("disk", "--name", "flash2")


@pytest.mark.parametrize("part, exc", [("unknown=x.img", KeyError), ("rootfs=big.img", ValueError)])
def test_disk_errors(project, run_ib, part, exc):
    with open(project.boot / "big.img", "wb") as f:
        f.truncate(0x1000000)

    with pytest.raises(exc):
        run_ib("disk", "--part", "plo=none", "--part", "kernel=none", "--part", part)


def test_ptable(tree, run_ib, psdisk):
    tree.write("nvm.yaml", """
        flash0:
          size: 0x100000
          block_size: 0x10000
          padding_byte: 0xff
          ptable_blocks: 2
          partitions:
            - {name: kernel, size: 0x40000}
            - {name: rootfs, size: 0x80000, type: jffs2}
            - {name: mtd, offs: 0, size: 0x100000, virtual: True}
        """)

    assert run_ib("ptable") == 0

    assert psdisk == [[str(tree.boot / "psdisk"), str(tree.boot / "flash0.ptable"), "-m", "0x100000,0x10000",
                       "-p", "kernel,0x0,0x40000,0x51", "-p", "rootfs,0x40000,0x80000,0x72"]]
    ptable = (tree.boot / "flash0.ptable").read_bytes()
    img = (tree.boot / "part_flash0_ptable.img").read_bytes()
    assert img == ptable + b"\xff" * (0x10000 - len(ptable)) + ptable


def test_ptable_as_regular_partition(tree, run_ib, psdisk):
    tree.write("nvm.yaml", """
        flash0:
          size: 0x100000
          block_size: 0x10000
          partitions:
            - {name: kernel, size: 0x40000}
            - {name: ptable, offs: 0xf0000}
        """)

    assert run_ib("ptable") == 0

    assert psdisk[0][-4:] == ["-p", "kernel,0x0,0x40000,0x51", "-p", "ptable,0xf0000,0x10000,0x51"]
    assert (tree.boot / "part_ptable.img").read_bytes() == (tree.boot / "flash0.ptable").read_bytes()


def test_ptable_missing_partition(project, run_ib, psdisk):
    with pytest.raises(ValueError, match="No ptable partition defined for flash flash0"):
        run_ib("ptable")


@pytest.mark.xfail(strict=True, reason="missing subcommand crashes instead of printing usage")
def test_no_subcommand(tree, run_ib):
    with pytest.raises(SystemExit):
        run_ib()


def test_missing_required_env(tree, run_ib, monkeypatch, capsys):
    monkeypatch.delenv("PREFIX_BOOT")

    with pytest.raises(SystemExit):
        run_ib("query", "x")
    assert "--prefix-boot" in capsys.readouterr().err

    # the same values can be given in command line instead
    assert run_ib("--prefix-boot", str(tree.boot), "query", "--nvm", "", "x") == 0


def run_process(*argv):
    return subprocess.run([sys.executable, str(IMAGE_BUILDER), *argv], capture_output=True, text=True,
                          env=os.environ.copy(), check=False)


def test_process_version():
    proc = run_process("--version")

    assert (proc.returncode, proc.stdout) == (0, "image_builder.py 1.0.0\n")


def test_process_script(project):
    proc = run_process("-vv", "script", "--script", "user.plo.yaml")

    assert proc.returncode == 0, proc.stderr
    assert "PLO script written to" in proc.stderr
    assert (project.plo / "user.plo").exists()


def test_process_error(tree):
    proc = run_process("query", "--nvm", "missing.yaml", "x")

    assert proc.returncode != 0
    assert "FileNotFoundError" in proc.stderr
