#
# syspage.py tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import struct

import pytest

import syspage
from syspage import HalImx6ull, Syspage, SyspageProg

LOAD = 0x80000000
ADDR = LOAD + 0x20

# Reference syspages written by phoenix-rtos-hostutils/syspagen (-a 32 -s 0x80000000:0x20:0x3e0) from plo scripts:
#   map ddr 0x80000000 0x87ffffff rwx
#   console 0.0
#   alias phoenix-armv7a7-imx6ull.bin 0x0 0x17000
#   alias dummyfs 0x17000 0x976c
#   app flash0 -x dummyfs;-N;devfs;-D ddr ddr
#   alias imx6ull-uart 0x21000 0x9730
#   app flash0 -x imx6ull-uart ddr ddr
#   alias psh 0x2b000 0x21960
#   app flash0 -x psh;-i;/etc/rc.psh ddr ddr
SYSPAGEN_APPS = bytes.fromhex(
    "60c9040028010000000000803800008060000080000000003800008038000080"
    "0000000000000080ffffff870700000000580000800000006464720000000000"
    "b0000080f8000080007001806c07028098000080010000009000008001000000"
    "8800008000000000000000000000000000000000000000005864756d6d796673"
    "3b2d4e3b64657666733b2d4400000000f8000080600000800010028030a70280"
    "e800008001000000e000008001000000d8000080000000000000000000000000"
    "000000000000000058696d7836756c6c2d7561727400000060000080b0000080"
    "00b0028060c90480300100800100000028010080010000002001008000000000"
    "00000000000000000000000000000000587073683b2d693b2f6574632f72632e"
    "7073680000000000")

# as above, but:
#   map ddr 0x80000000 0x87ffffff rwx
#   map ocram 0x900000 0x920000 rw
#   console 0.1
#   alias phoenix-armv7a7-imx6ull.bin 0x0 0x17000
#   alias dummyfs 0x17000 0x976c
#   app flash0 -x dummyfs ddr ddr;ocram
#   alias flash-test 0x21000 0x1234
#   app flash0 flash-test ocram ddr
SYSPAGEN_MAPS = bytes.fromhex(
    "34220200f8000000000000803800008088000080010000006000008060000080"
    "0000000000000080ffffff870700000000580000800000006464720000000000"
    "3800008038000080000000000000900000009200030000000180000080000000"
    "6f6372616d000000d0000080d0000080007001806c070280c000008001000000"
    "b800008002000000b00000800000000000010000000000000000000000000000"
    "5864756d6d796673000000000000000088000080880000800010028034220280"
    "08010080010000000001008001000000f8000080000000000000000000000000"
    "0100000000000000666c6173682d74657374000000000000")


def imx6ull(sp, image_size):
    """Full syspage as embedded in the plo-less kernel image"""
    return HalImx6ull().pack(image_size=image_size) + sp.pack(ADDR, HalImx6ull.SIZE, LOAD)


def prog(argv, offs, size, imaps=("ddr",), dmaps=("ddr",), exec=True):
    return SyspageProg(argv, LOAD + offs, LOAD + offs + size, list(imaps), list(dmaps), exec)


def test_same_as_syspagen_apps():
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x87ffffff, "rwx")
    sp.add_prog(prog("dummyfs;-N;devfs;-D", 0x17000, 0x976c))
    sp.add_prog(prog("imx6ull-uart", 0x21000, 0x9730))
    sp.add_prog(prog("psh;-i;/etc/rc.psh", 0x2b000, 0x21960))

    assert imx6ull(sp, 0x4c960) == SYSPAGEN_APPS


def test_same_as_syspagen_maps():
    sp = Syspage(console=syspage.parse_console("0.1"))
    sp.add_map("ddr", 0x80000000, 0x87ffffff, "rwx")
    sp.add_map("ocram", 0x900000, 0x920000, "wr")
    sp.add_prog(prog("dummyfs", 0x17000, 0x976c, dmaps=("ddr", "ocram")))
    sp.add_prog(prog("flash-test", 0x21000, 0x1234, imaps=("ocram",), exec=False))

    assert imx6ull(sp, 0x22234) == SYSPAGEN_MAPS


def test_common_part():
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x87ffffff, "rwx")

    # only the HAL part size matters - its contents may be filled in independently (eg. by plo)
    assert struct.unpack_from("<IIIII", sp.pack(ADDR, 4, LOAD)) == (0x40, LOAD, ADDR + 0x18, 0, 0)
    assert struct.unpack_from("<IIIII", sp.pack(ADDR, 0x10, LOAD)) == (0x50, LOAD, ADDR + 0x28, 0, 0)


def test_empty():
    sp = Syspage()

    assert imx6ull(sp, 0x100) == struct.pack("<IIIIII", 0x100, 0x18, LOAD, 0, 0, 0)


def test_map_errors():
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x88000000, "rwx")

    with pytest.raises(ValueError, match="overlaps"):
        sp.add_map("ddr", 0x90000000, 0x91000000, "rw")
    with pytest.raises(ValueError, match="overlaps"):
        sp.add_map("ddr2", 0x87fff000, 0x89000000, "rw")
    with pytest.raises(ValueError, match="invalid map attribute 'q'"):
        sp.add_map("sram", 0x100000, 0x200000, "rwq")
    sp.add_map("sram", 0x88000000, 0x88100000, "rwxscb")

    assert [(m.name, m.attr) for m in sp.maps] == [("ddr", 0x07), ("sram", 0x3f)]


def test_prog_unknown_map():
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x88000000, "rwx")

    with pytest.raises(ValueError, match="psh: unknown map 'sram'"):
        sp.add_prog(prog("psh", 0, 0x10, dmaps=("ddr", "sram")))


def test_get_map():
    sp = Syspage()
    sp.add_map("ddr", 0x80000000, 0x88000000, "rwx")

    assert (sp.get_map("ddr").start, sp.get_map("ddr").end) == (0x80000000, 0x88000000)
    with pytest.raises(ValueError, match="unknown map 'sram'"):
        sp.get_map("sram")


@pytest.mark.parametrize("text, minor", [("0.0", 0), ("1.2", 2), ("0.0x10", 16)])
def test_parse_console(text, minor):
    assert syspage.parse_console(text) == minor


@pytest.mark.parametrize("text", ["0", "a.1", "0.b", "0.1.2"])
def test_parse_console_invalid(text):
    with pytest.raises(ValueError):
        syspage.parse_console(text)


def test_syspage_area():
    target = syspage.get_ploless_target("armv7a7-imx6ull")

    symbols = {"init_vectors": 0x80000000, "syspage_data": 0x80000020, "plugin_ivt": 0x80000400}
    assert target.syspage_area(symbols) == (0x20, 0x3e0)


def test_get_ploless_target():
    target = syspage.get_ploless_target("armv7a7-imx6ull-midash")

    assert (target.load_addr, target.window) == (0x80000000, ("init_vectors", "syspage_data", "plugin_ivt"))
    with pytest.raises(ValueError, match=r"armv7a9-zynq7000-qemu: .* \(supported plo-less targets: armv7a7-imx6ull\)"):
        syspage.get_ploless_target("armv7a9-zynq7000-qemu")
