#
# strip.py tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import struct
import sys

import pytest

import strip
from elfgen import KERNEL_SEGMENTS, PF_R, PT_GNU_EH_FRAME, SHT_PROGBITS, Section, Segment, make_elf32, rel_section
from strip import ElfParser, PhFlags, PhType


def test_program_headers(tree):
    path = make_elf32(tree.root / "k.elf", KERNEL_SEGMENTS)

    with open(path, "rb") as f:
        phdrs = [ph for ph, _ in ElfParser(f).get_program_headers()]

    assert [(ph.p_type, ph.p_flags, ph.p_vaddr, ph.p_memsz) for ph in phdrs] == [
        (PhType.PT_ARM_EXIDX, PhFlags.PF_R, 0xc0016e10, 0x8),
        (PhType.PT_LOAD, PhFlags.PF_R | PhFlags.PF_X, 0xc0000000, 0x16e18),
        (PhType.PT_LOAD, PhFlags.PF_R | PhFlags.PF_W, 0xc0018000, 0x186ec),
        (PhType.PT_GNU_STACK, PhFlags.PF_R | PhFlags.PF_W, 0, 0),
    ]


@pytest.mark.xfail(strict=True, reason="PT_GNU_EH_FRAME value typo (0x6474e50 instead of 0x6474e550)")
def test_gnu_eh_frame_segment(tree):
    path = make_elf32(tree.root / "eh.elf", [Segment(PT_GNU_EH_FRAME, PF_R)])

    with open(path, "rb") as f:
        [(ph, _)] = list(ElfParser(f).get_program_headers())

    assert ph.p_type == PhType.PT_GNU_EH_FRAME


@pytest.mark.parametrize("ident, exc", [
    (b"\x7fELG\x01\x01", ValueError),
    (b"\x7fELF\x02\x01", NotImplementedError),
])
def test_invalid_elf(tree, ident, exc):
    path = make_elf32(tree.root / "bad.elf", ident=ident)

    with open(path, "rb") as f, pytest.raises(exc):
        ElfParser(f)


def rel_elf(tree):
    return make_elf32(tree.root / "rel.elf", sections=[
        Section(".text", SHT_PROGBITS, b"\xaa" * 16),
        rel_section(".rel.text", [(0x0, (5 << 8) | 0x02), (0x8, (0x1234 << 8) | 0x1c)]),
    ])


def relocations(data):
    with open(data, "rb") as f:
        elf = ElfParser(f)
        return [(r.r_offset, r.r_info) for s, _ in elf.get_sections() if s.sh_type == strip.ShType.SHT_REL
                for r, _ in elf.get_relocations(s)]


def test_remove_symtab_references(tree):
    src = rel_elf(tree)
    out = tree.root / "out.elf"

    with open(out, "w+b") as f:
        strip.remove_symtab_references(src, f)

    # symbol index is cleared, relocation type and everything else stays intact
    assert relocations(out) == [(0x0, 0x02), (0x8, 0x1c)]
    orig_rel = struct.pack("<IIII", 0x0, (5 << 8) | 0x02, 0x8, (0x1234 << 8) | 0x1c)
    new_rel = struct.pack("<IIII", 0x0, 0x02, 0x8, 0x1c)
    assert out.read_bytes() == src.read_bytes().replace(orig_rel, new_rel)


def test_strip_wrapper(tree, monkeypatch):
    src = rel_elf(tree)
    out = tree.root / "stripped.elf"
    fake_strip = tree.write("fake_strip.py", """
        import shutil, sys
        shutil.copy(sys.argv[-1], sys.argv[sys.argv.index("-o") + 1])
        """)

    monkeypatch.setattr(sys, "argv", ["strip.py", sys.executable, str(fake_strip), "-o", str(out), str(src)])
    strip.strip_wrapper()

    assert relocations(out) == [(0x0, 0x02), (0x8, 0x1c)]


@pytest.mark.parametrize("argv", [["-s", "-o", "out", "in"], ["strip", "in"]])
def test_strip_wrapper_usage(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", ["strip.py", *argv])

    with pytest.raises(SystemExit) as ex:
        strip.strip_wrapper()

    assert ex.value.code == 1
    assert "Usage:" in capsys.readouterr().err
