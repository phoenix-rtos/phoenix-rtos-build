#
# image_builder.py kernel-image subcommand tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import struct

import pytest

from conftest import KERNEL
from elfgen import KERNEL_SEGMENTS, SHT_PROGBITS, Section, make_elf32, symtab_sections
from syspage import HalImx6ull, Syspage
from test_syspage import ADDR, LOAD, SYSPAGEN_APPS, prog

WINDOW = slice(0x20, 0x400)

SCRIPT = """
    size: 0
    contents:
      - map ddr 0x80000000 0x87ffffff rwx
      - console 0.0
      - kernelimg {{ env.BOOT_DEVICE }}
      - app {{ env.BOOT_DEVICE }} -x dummyfs;-N;devfs;-D ddr ddr
      - app {{ env.BOOT_DEVICE }} -x imx6ull-uart ddr ddr
      - action: app
        device: '{{ env.BOOT_DEVICE }}'
        flags: EXEC
        filename: psh
        args: '-i;/etc/rc.psh'
        text_map: ddr
        data_maps: ddr
    """


@pytest.fixture
def project(tree):
    tree.write("nvm.yaml", """
        flash0:
          size: 0x1000000
          block_size: 0x40000
          padding_byte: 0xff
          partitions:
            - {name: kernel, size: 0x80000}
            - {name: small, size: 0x40000}
        """)
    tree.write("kernel.yaml", SCRIPT)

    # kernel binary with empty syspage area + unstripped ELF with symbols defining its location
    kernel = tree.kernel()
    data = bytearray(kernel.read_bytes())
    data[WINDOW] = bytes(0x3e0)
    kernel.write_bytes(data)
    (tree.root / "prog").mkdir()
    make_elf32(tree.root / "prog" / f"{KERNEL}.elf", KERNEL_SEGMENTS, [
        Section(".init", SHT_PROGBITS, bytes(4)),
        *symtab_sections({"init_vectors": 0xc0000000, "syspage_data": 0xc0000020, "plugin_ivt": 0xc0000400}),
    ])

    tree.payload("dummyfs", 0x976c)
    tree.payload("imx6ull-uart", 0x9730)
    tree.payload("psh", 0x21960)
    return tree


def kernel_image(run_ib, tree, *args):
    return run_ib("kernel-image", "--kernel-elf", str(tree.root / "prog" / f"{KERNEL}.elf"), *args)


def expected_image(tree, padding=b"\0"):
    kernel = bytearray((tree.prog / f"{KERNEL}.bin").read_bytes())
    kernel[WINDOW] = SYSPAGEN_APPS.ljust(0x3e0, b"\0")
    img = bytes(kernel)
    for name, offs in (("dummyfs", 0x17000), ("imx6ull-uart", 0x21000), ("psh", 0x2b000)):
        img = img.ljust(offs, padding) + (tree.prog / name).read_bytes()
    return img


def test_same_as_syspagen(project, run_ib):
    assert kernel_image(run_ib, project, "--script", "kernel.yaml", "--out", "phoenix-kernel.img") == 0

    img = (project.boot / "phoenix-kernel.img").read_bytes()
    assert len(img) == 0x4c960
    assert img == expected_image(project)


def test_partition(project, run_ib):
    assert kernel_image(run_ib, project, "--script", "kernel.yaml", "--name", "kernel") == 0
    assert kernel_image(run_ib, project, "--script", "kernel.yaml", "--name", "flash0:kernel",
                        "--out", str(project.root / "k.img")) == 0

    assert (project.boot / "part_kernel.img").read_bytes() == expected_image(project, padding=b"\xff")
    assert (project.root / "k.img").read_bytes() == expected_image(project, padding=b"\xff")
    with pytest.raises(AssertionError, match="exceeds total size"):
        kernel_image(run_ib, project, "--script", "kernel.yaml", "--name", "small")


def test_load_addr(project, run_ib):
    assert kernel_image(run_ib, project, "--script", "kernel.yaml", "--out", "k.img", "--load-addr", "0x80100000") == 0

    img = (project.boot / "k.img").read_bytes()
    size, pkernel, maps, progs = struct.unpack_from("<IIII", img, 0x24)
    assert (size, pkernel, maps, progs) == (len(SYSPAGEN_APPS), 0x80100000, 0x80100038, 0x80100060)


def test_load_addr_outside_map(project, run_ib):
    with pytest.raises(ValueError, match=r"kernel.yaml: dummyfs at 0x90017000-0x9002076c is outside of map 'ddr'"):
        kernel_image(run_ib, project, "--script", "kernel.yaml", "--out", "k.img", "--load-addr", "0x90000000")


def test_blob(project, run_ib):
    project.payload("logo", 0x1234)
    project.write("blob.yaml", SCRIPT + "  - blob flash0 logo ddr\n")

    assert kernel_image(run_ib, project, "--script", "blob.yaml", "--out", "k.img") == 0

    img, expected = (project.boot / "k.img").read_bytes(), expected_image(project)
    assert (img[:0x20], img[0x400:0x4c960]) == (expected[:0x20], expected[0x400:])
    assert img[0x4c960:] == bytes(0x4d000 - 0x4c960) + (project.prog / "logo").read_bytes()

    # blob is not executed and has no maps (as in plo)
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x87ffffff, "rwx")
    for argv, offs, size in (("dummyfs;-N;devfs;-D", 0x17000, 0x976c), ("imx6ull-uart", 0x21000, 0x9730),
                             ("psh;-i;/etc/rc.psh", 0x2b000, 0x21960)):
        sp.add_prog(prog(argv, offs, size))
    sp.add_prog(prog("logo", 0x4d000, 0x1234, imaps=(), dmaps=(), exec=False))
    syspage = HalImx6ull().pack(image_size=len(img)) + sp.pack(ADDR, HalImx6ull.SIZE, LOAD)
    assert img[WINDOW] == syspage.ljust(0x3e0, b"\0")


def test_blob_outside_map(project, run_ib):
    project.payload("logo", 0x1234)
    project.write("blob.yaml", SCRIPT + "  - map ocram 0x900000 0x920000 rw\n      - blob flash0 logo ocram\n")

    with pytest.raises(ValueError, match=r"logo at 0x8004d000-0x8004e234 is outside of map 'ocram'"):
        kernel_image(run_ib, project, "--script", "blob.yaml", "--out", "k.img")


@pytest.mark.parametrize("args, error", [
    (["--name", "missing"], "Can't find target partition"),
    ([], "Output image not defined"),
])
def test_output_errors(project, run_ib, args, error):
    with pytest.raises(ValueError, match=error):
        kernel_image(run_ib, project, "--script", "kernel.yaml", *args)


def test_unsupported_target(project, run_ib, monkeypatch):
    monkeypatch.setenv("TARGET", "armv7a9-zynq7000-qemu")

    with pytest.raises(ValueError, match="supported plo-less targets: armv7a7-imx6ull"):
        kernel_image(run_ib, project, "--script", "kernel.yaml", "--out", "k.img")


@pytest.mark.parametrize("cmd, error", [
    ("wait 500", "command not supported in kernel image: wait 500$"),
    ("phfs usb0 1.2 phoenixd", "command not supported in kernel image: phfs usb0 1.2 phoenixd$"),
    ("call flash0 user.plo 0x0 dabaabad", "command not supported in kernel image: PloCmdCall"),
    ("kernel flash0", r"`kernel` \(ELF loaded by plo\) can't be used in kernel image - use `kernelimg`"),
    ("kernelimg flash0", "`kernelimg` has to be the first program"),
    ("app flash0 -xn psh ddr ddr", "`app -xn psh`: execute in place is not supported"),
])
def test_unsupported_commands(project, run_ib, cmd, error):
    project.write("bad.yaml", f"""
        size: 0
        contents:
          - map ddr 0x80000000 0x87ffffff rwx
          - kernelimg flash0
          - {cmd}
        """)

    with pytest.raises(ValueError, match=f"bad.yaml: {error}"):
        kernel_image(run_ib, project, "--script", "bad.yaml", "--out", "k.img")


@pytest.mark.parametrize("cmd", ["app flash0 -x psh;-i ddr ddr", "blob flash0 psh ddr"])
def test_app_before_kernel(project, run_ib, cmd):
    project.write("bad.yaml", f"""
        size: 0
        contents:
          - map ddr 0x80000000 0x87ffffff rwx
          - {cmd}
          - kernelimg flash0
        """)

    with pytest.raises(ValueError, match=r"bad.yaml: `(app psh;-i|blob psh)` before `kernelimg`"):
        kernel_image(run_ib, project, "--script", "bad.yaml", "--out", "k.img")


@pytest.mark.parametrize("header", ["size: 0x1000", "size: 0\noffs: 0x1000", "size: 0\nis_relative: True"])
def test_script_header(project, run_ib, header):
    project.write("bad.yaml", header + "\ncontents:\n  - kernelimg flash0\n")

    with pytest.raises(ValueError, match="needs `size: 0`"):
        kernel_image(run_ib, project, "--script", "bad.yaml", "--out", "k.img")


def test_no_kernel(project, run_ib):
    project.write("bad.yaml", "size: 0\ncontents:\n  - map ddr 0x80000000 0x87ffffff rwx\n")

    with pytest.raises(ValueError, match="no `kernelimg` command"):
        kernel_image(run_ib, project, "--script", "bad.yaml", "--out", "k.img")


def test_stripped_elf(project, run_ib):
    with pytest.raises(ValueError, match="symbol 'init_vectors' not found"):
        run_ib("kernel-image", "--kernel-elf", str(project.prog / f"{KERNEL}.elf"), "--script", "kernel.yaml",
               "--out", "k.img")


def test_syspage_area_not_empty(project, run_ib):
    project.kernel()

    with pytest.raises(ValueError, match="no empty syspage area at 0x20"):
        kernel_image(run_ib, project, "--script", "kernel.yaml", "--out", "k.img")


def test_syspage_too_large(project, run_ib):
    project.write("big.yaml", SCRIPT + "  - app flash0 -x psh;" + "a" * 700 + " ddr ddr\n")

    with pytest.raises(ValueError, match=r"syspage too large \(1064 > 992 bytes"):
        kernel_image(run_ib, project, "--script", "big.yaml", "--out", "k.img")
