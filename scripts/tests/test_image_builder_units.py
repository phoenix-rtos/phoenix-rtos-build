#
# image_builder.py unit tests
#
# Copyright 2026 Phoenix Systems
# Author: Marek Bialowas
#
# SPDX-License-Identifier: BSD-3-Clause
#

import io

import jinja2
import pytest

import image_builder as ib
from conftest import KERNEL
from elfgen import PF_R, PF_X, PT_LOAD, Segment, make_elf32
from image_builder import (CmdAppFlags, PloCmdAlias, PloCmdApp, PloCmdCall, PloCmdConsole, PloCmdFactory,
                           PloCmdGeneric, PloCmdKernel, PloCmdMap, PloScript, PloScriptEncoding, ProgInfo)
from nvm_config import read_nvm

ENC = PloScriptEncoding.STRING_MAGIC_V1


def emit(cmd, payload_offs=0, is_relative=False):
    """Returns (emitted text, new payload offset, ProgInfo)"""
    out = io.StringIO()
    offs, prog = cmd.emit(out, ENC, payload_offs, is_relative)
    return out.getvalue(), offs, prog


def test_round_up():
    assert [ib.round_up(x, 0x1000) for x in (0, 1, 0x1000, 0x1001)] == [0, 0x1000, 0x1000, 0x2000]


def test_get_elf_sizes(tree):
    tree.kernel()

    assert ib.get_elf_sizes(tree.prog / f"{KERNEL}.elf") == (0xc0000000, 0x17000, 0xc0018000, 0x19000)


def test_get_elf_sizes_needs_single_text(tree):
    path = make_elf32(tree.root / "two.elf", [Segment(PT_LOAD, PF_R | PF_X)] * 2)

    with pytest.raises(AssertionError):
        ib.get_elf_sizes(path)


def test_prog_info(tree):
    assert str(ProgInfo(tree.root / "a", 0x1000, 0x80)) == f"{'a':30s} (offs={'0x1000':>10s}, size={'0x80':>8s})"
    assert str(ProgInfo(tree.root / "a", 0, 0x80, 0x100)).endswith(f"size={'0x80':>8s} / {'0x100':>8s} 50%)")

    with pytest.raises(ValueError, match="exceeds max_size"):
        ProgInfo(tree.root / "a", 0, 0x101, 0x100)


@pytest.mark.parametrize("value, expected, text", [
    ("none", CmdAppFlags.NONE, ""), ("Exec", CmdAppFlags.EXEC, " -x"),
    ("EXEC_NO_COPY", CmdAppFlags.EXEC_NO_COPY, " -xn"), (1, CmdAppFlags.EXEC, " -x"),
])
def test_app_flags(value, expected, text):
    assert CmdAppFlags(value) == expected
    assert CmdAppFlags(value).emit_as_string() == text


def test_app_flags_invalid():
    with pytest.raises(ValueError, match="not a valid CmdAppFlags"):
        CmdAppFlags("copy")


class TestFactory:
    def test_kernel(self, tree):
        tree.kernel()

        elf = PloCmdFactory.build("kernel flash0")
        img = PloCmdFactory.build("kernelimg flash0")

        assert isinstance(elf, PloCmdKernel) and isinstance(img, PloCmdKernel)
        assert (elf.name, elf.device, elf.filename) == ("kernel", "flash0", f"{KERNEL}.elf")
        assert (img.name, img.filename, img.size, img.abspath) == ("kernelimg", f"{KERNEL}.bin", 0x16e18,
                                                                   tree.prog / f"{KERNEL}.bin")

    def test_app(self, tree):
        tree.payload("dummyfs", 0x100)

        cmd = PloCmdFactory.build("app flash0 -x dummyfs;-N;devfs ddr ddr;sram")

        assert isinstance(cmd, PloCmdApp)
        assert (cmd.name, cmd.device, cmd.flags) == ("app", "flash0", CmdAppFlags.EXEC)
        assert (cmd.text_map, cmd.data_maps) == ("ddr", "ddr;sram")
        # string form: args are kept verbatim (as a single element)
        assert (cmd.filename, cmd.args, cmd.size) == ("dummyfs", ["-N;devfs"], 0x100)
        assert cmd.abspath == tree.prog / "dummyfs"

    def test_app_no_exec(self, tree):
        tree.payload("psh", 0x10)

        assert PloCmdFactory.build("app flash0 psh ddr ddr").flags == CmdAppFlags.NONE
        assert PloCmdFactory.build("app flash0 -xn psh ddr ddr").flags == CmdAppFlags.EXEC_NO_COPY

    def test_app_from_dict(self, tree):
        tree.payload("psh", 0x10)

        cmd = PloCmdFactory.build(action="app", device="flash0", filename="psh", args="-i;;/etc/rc.psh;",
                                  flags="EXEC", text_map="ddr", data_maps="ddr")

        assert (cmd.flags, cmd.filename, cmd.args) == (CmdAppFlags.EXEC, "psh", ["-i", "/etc/rc.psh"])
        assert PloCmdFactory.build(name="app", device="flash0", filename="psh", args=["-i", ""],
                                   text_map="ddr", data_maps="ddr").args == ["-i"]

    def test_explicit_extra_flags_take_precedence(self, tree):
        tree.payload("psh", 0x10)

        assert PloCmdFactory.build("app flash0 -x psh ddr ddr", extra_flags="-xn").flags == CmdAppFlags.EXEC_NO_COPY

    def test_blob_from_rootfs(self, tree):
        tree.payload("etc/hostid", 4, tree.rootfs)

        cmd = PloCmdFactory.build("blob flash0 /etc/hostid ddr")

        assert (cmd.name, cmd.filename, cmd.abspath) == ("blob", "hostid", tree.rootfs / "etc/hostid")
        assert (cmd.text_map, cmd.data_maps) == ("", "ddr")

    def test_call(self):
        cmd = PloCmdFactory.build("call flash0 user.plo 0x10000 dabaabad")

        assert isinstance(cmd, PloCmdCall)
        assert (cmd.device, cmd.filename, cmd.offset, cmd.target_magic) == ("flash0", "user.plo", 0x10000, "dabaabad")
        assert (cmd.set_base, cmd.absolute) == (False, False)
        assert PloCmdFactory.build("call -setbase flash0 user.plo 0x10000 dabaabad").set_base
        assert PloCmdFactory.build("call -absolute flash0 user.plo 0x10000 dabaabad").absolute

    def test_map(self):
        cmd = PloCmdFactory.build("map per    0x50000000 0x60000000 rw")

        assert isinstance(cmd, PloCmdMap)
        assert (cmd.map_name, cmd.start, cmd.end, cmd.attrs) == ("per", 0x50000000, 0x60000000, "rw")
        assert emit(cmd) == ("map per    0x50000000 0x60000000 rw\n", 0, None)

    def test_console(self):
        cmd = PloCmdFactory.build("console 0.2")

        assert isinstance(cmd, PloCmdConsole)
        assert (cmd.device, cmd.mirrors) == ("0.2", [])
        assert emit(cmd) == ("console 0.2\n", 0, None)
        assert PloCmdFactory.build("console 0.0 3.0 3.1").mirrors == ["3.0", "3.1"]

    @pytest.mark.parametrize("text, error", [
        ("map ddr 0x0", "expected `map <name> <start> <end> <attributes>`"),
        ("map ddr 0x0 end rwx", "invalid literal"),
        ("console", "expected `console <major>.<minor>"),
    ])
    def test_map_console_errors(self, text, error):
        with pytest.raises(ValueError, match=error):
            PloCmdFactory.build(text)

    @pytest.mark.parametrize("text, expected", [
        ("wait 500", "wait 500"), ("go!", "go!"), ("%alias -b 0x100", "alias -b 0x100"), ("%  go!", "go!"),
    ])
    def test_generic(self, text, expected):
        cmd = PloCmdFactory.build(text)

        assert type(cmd) is PloCmdGeneric
        assert cmd.cmd == expected

    def test_call_substring(self):
        assert type(PloCmdFactory.build("ca foo bar")) is PloCmdGeneric

    def test_empty_name(self):
        with pytest.raises(ValueError, match="unknown CMD format"):
            PloCmdFactory.build(name="")


class TestApp:
    def test_required_attrs(self, tree):
        tree.payload("psh", 0x10)

        with pytest.raises(TypeError, match="'text_map' not present"):
            PloCmdFactory.build(action="app", device="flash0", filename="psh", data_maps="ddr")
        with pytest.raises(TypeError, match="'data_maps' not present"):
            PloCmdFactory.build("blob flash0 psh")

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            PloCmdFactory.build("app flash0 -x psh ddr ddr")

    def test_emit(self, tree):
        tree.payload("dummyfs", 0x1234)

        text, offs, prog = emit(PloCmdFactory.build("app flash0 -x dummyfs;-N;devfs ddr ddr"), 0x3000)

        assert text == "alias dummyfs 0x3000 0x1234\napp flash0 -x dummyfs;-N;devfs ddr ddr\n"
        assert offs == 0x5000
        assert (prog.path, prog.offs, prog.size) == (tree.prog / "dummyfs", 0x3000, 0x1234)

    def test_emit_blob(self, tree):
        tree.payload("etc/logo", 0x10, tree.rootfs)

        text, offs, prog = emit(PloCmdFactory.build("blob flash0 /etc/logo ddr"), 0x1000, is_relative=True)

        assert text == "alias -r logo 0x1000 0x10\nblob flash0 logo ddr\n"
        assert (offs, prog.path) == (0x2000, tree.rootfs / "etc/logo")

    @pytest.mark.parametrize("flags, text", [(1, "app flash0 -x psh"), (0, "app flash0 psh"), ("", "app flash0 psh"),
                                             (None, "app flash0 psh")])
    def test_emit_int_flags(self, tree, flags, text):
        tree.payload("psh", 0x10)
        cmd = PloCmdFactory.build(action="app", device="flash0", filename="psh", flags=flags, text_map="ddr",
                                  data_maps="ddr")

        assert f"{text} ddr ddr" in emit(cmd)[0]


class TestAlias:
    @pytest.mark.parametrize("set_base, is_relative, text, new_offs", [
        (False, False, "alias f 0x2000 0x1234\n", 0x4000),
        (False, True, "alias -r f 0x2000 0x1234\n", 0x4000),
        (True, False, "alias -b 0x2000\nalias f 0x2000 0x1234\n", 0x4000),
        # base change in relative script resets the payload offset
        (True, True, "alias -rb 0x2000\nalias -r f 0x0 0x1234\n", 0x2000),
    ])
    def test_emit(self, tree, set_base, is_relative, text, new_offs):
        out, offs, prog = emit(PloCmdAlias("f", 0x1234, set_base=set_base), 0x2000, is_relative)

        assert (out, offs) == (text, new_offs)
        assert (prog.path, prog.size) == (tree.prog / "f", 0x1234)


class TestKernel:
    def test_emit_elf(self, tree):
        tree.kernel()

        text, offs, prog = emit(PloCmdFactory.build("kernel flash0"), 0x1000, is_relative=True)

        size = (tree.prog / f"{KERNEL}.elf").stat().st_size
        assert text == f"alias -r {KERNEL}.elf 0x1000 {size:#x}\nkernel flash0\n"
        assert (offs, prog.path, prog.size) == (0x2000, tree.prog / f"{KERNEL}.elf", size)

    def test_emit_img(self, tree):
        tree.kernel()

        text, offs, _ = emit(PloCmdFactory.build("kernelimg flash0"), 0x20000)

        assert text == (f"alias {KERNEL}.bin 0x20000 0x16e18\n"
                        f"kernelimg flash0 {KERNEL}.bin 0xc0000000 0x17000 0xc0018000 0x19000\n")
        assert offs == 0x37000


class TestCall:
    def test_emit(self):
        # FIXME in image_builder: alias size is hardcoded (not taken from the called script)
        text, offs, prog = emit(PloCmdFactory.build("call flash0 user.plo 0x10000 dabaabad"), 0x3000)

        assert text == "alias user.plo 0x10000 0x1000\ncall flash0 user.plo dabaabad\n"
        assert (offs, prog) == (0x3000, None)

    def test_emit_relative(self):
        def text(cmd, is_relative):
            return emit(PloCmdFactory.build(cmd), 0, is_relative)[0]

        assert text("call flash0 u.plo 0x10 ab", True).startswith("alias -r u.plo 0x10 ")
        assert text("call -absolute flash0 u.plo 0x10 ab", True).startswith("alias u.plo")
        assert text("call -setbase flash0 u.plo 0x10 ab", False).startswith("alias -b 0x10\n")


class TestScript:
    def test_payload_after_script(self, tree):
        tree.payload("psh", 0x10)
        script = PloScript(size=0x1000, offs=0x8000, magic="dabaabad")
        script.contents = [PloCmdFactory.build("wait 500"), PloCmdFactory.build("app flash0 -x psh ddr ddr")]

        out = io.StringIO()
        progs = script.write(out)

        assert out.getvalue() == "dabaabad\nwait 500\nalias psh 0x9000 0x10\napp flash0 -x psh ddr ddr\n\0"
        assert [(p.path, p.offs, p.size) for p in progs] == [(tree.prog / "psh", 0x9000, 0x10)]

    def test_types_from_str(self):
        assert (PloScript(size="4096", offs="512").size, PloScript(size="4096", offs="512").offs) == (0x1000, 0x200)

    def test_types_from_hex_str(self):
        assert PloScript(size="0x1000").size == 0x1000

    def test_invalid_magic(self):
        with pytest.raises(ValueError, match="invalid len"):
            PloScript(size=0x100, magic="dabaaba").write(io.StringIO())

    def test_too_large(self):
        script = PloScript(size=8)
        script.contents = [PloCmdFactory.build("wait 500")]

        with pytest.raises(ValueError, match="too large"):
            script.write(io.StringIO())

    def test_debug_encoding(self):
        script = PloScript(size=0x100)
        script.contents = [PloCmdFactory.build("wait 500")]

        out = io.StringIO()
        script.write(out, PloScriptEncoding.DEBUG_ASDICT)

        assert out.getvalue() == "{'name': 'unknown', 'cmd': 'wait 500'}\n\0"


class TestTemplates:
    def test_render_val(self, monkeypatch):
        monkeypatch.setenv("BOOT_DEVICE", "nor0")

        assert ib.render_val("{{ env.BOOT_DEVICE }} {{ x + 1 }}", x=1) == "nor0 2"
        assert ib.render_val(["{{ x }}", {"k": "{{ x }}", "n": 5}], x="a") == ["a", {"k": "a", "n": 5}]
        assert ib.render_val(None) is None

    def test_render_val_strict(self):
        with pytest.raises(jinja2.UndefinedError):
            ib.render_val("{{ env.NOT_DEFINED_ANYWHERE }}")

    @pytest.mark.parametrize("value, expected", [
        (True, True), (False, False), ("", False), ("No", False), ("false", False), ("n", False), ("0", False),
        ("yes", True), ("True", True), ("1", True),
    ])
    def test_str2bool(self, value, expected):
        assert ib.str2bool(value) is expected

    @pytest.mark.parametrize("value", [None, 0])
    def test_str2bool_non_str(self, value):
        assert ib.str2bool(value) is False

    def test_nvm_to_dict(self, tree):
        nvm = read_nvm(tree.write("nvm.yaml", """
            flash0:
              size: 0x10000
              block_size: 0x1000
              partitions:
                - {name: kernel}
            """))

        d = ib.nvm_to_dict(nvm)

        assert d["flash0"]["kernel"] is nvm[0].parts[0]
        assert d["flash0"]["_meta"] == {"name": "flash0", "size": 0x10000, "block_size": 0x1000, "padding_byte": 0,
                                        "ptable_size": 0, "parts": nvm[0].parts}


class TestParseScript:
    def parse(self, tree, text):
        nvm = read_nvm(tree.write("nvm.yaml", """
            flash0:
              size: 0x100000
              block_size: 0x1000
              partitions:
                - {name: kernel, offs: 0x20000, size: 0x10000}
            """))
        return ib.parse_plo_script(nvm, tree.write("s.yaml", text))

    def test_fields_and_conditions(self, tree, monkeypatch):
        monkeypatch.setenv("RAM_SCRIPT", "1")
        script = self.parse(tree, """
            size: '{{ nvm.flash0.kernel.size }}'
            offs: '{{ nvm.flash0.kernel.offs }}'
            magic: '{{ env.MAGIC_USER_SCRIPT }}'
            contents:
              - wait {{ script.size }}
              - if: '{{ env.RAM_SCRIPT }}'
                str: console 0.0
              - if: '{{ not(env.RAM_SCRIPT) | default(false) }}'
                str: console 1.0
              - if: False
                str: go!
              - action: call
                device: '{{ env.BOOT_DEVICE }}'
                filename: user.plo
                offset: '{{ nvm.flash0.kernel.offs }}'
                target_magic: '{{ env.MAGIC_USER_SCRIPT }}'
            """)

        assert (script.size, script.offs, script.magic, script.is_relative) == (0x10000, 0x20000, "dabaabad", False)
        assert [type(c) for c in script.contents] == [PloCmdGeneric, PloCmdConsole, PloCmdCall]
        assert [c.cmd for c in script.contents[:2]] == ["wait 65536", "console 0.0"]
        assert (script.contents[2].device, script.contents[2].offset) == ("flash0", 0x20000)

    def test_error_context(self, tree):
        with pytest.raises(ValueError, match="Failed to parse PLO CMD: app flash0 missing ddr ddr") as ex:
            self.parse(tree, """
                size: 0x1000
                contents:
                  - app flash0 missing ddr ddr
                """)

        assert isinstance(ex.value.__cause__, FileNotFoundError)


class TestImageWriter:
    def test_set_offset(self):
        f = io.BytesIO()

        ib.set_offset(f, 1300, 0xff)  # more than one internal chunk
        f.write(b"abc")
        ib.set_offset(f, 10, 0)       # back into already written data
        f.write(b"x")

        assert f.getvalue() == b"\xff" * 10 + b"x" + b"\xff" * 1289 + b"abc"

    def test_add_to_image(self, tree):
        src = tree.payload("data", 1025)
        f = io.BytesIO(b"\1\2")

        assert ib.add_to_image(f, 4, src, 0xee) == 1025
        assert f.getvalue() == b"\1\2\xee\xee" + src.read_bytes()

    def test_write_image(self, tree):
        a, b = tree.payload("a", 0x10), tree.payload("b", 0x10)
        out = tree.boot / "img"
        out.write_bytes(b"old contents to be removed" * 100)

        assert ib.write_image([ProgInfo(a, 0, 0x10), ProgInfo(b, 0x20, 0x10)], out, 0x30, 0x55) == 0
        assert out.read_bytes() == a.read_bytes() + b"\x55" * 0x10 + b.read_bytes()

    def test_write_image_errors(self, tree):
        a = tree.payload("a", 0x10)

        with pytest.raises(ValueError, match="Empty partition"):
            ib.write_image([], tree.boot / "img", 0x100, 0)
        with pytest.raises(AssertionError, match="exceeds total size"):
            ib.write_image([ProgInfo(a, 0x100, 0x10)], tree.boot / "img", 0x100, 0)
        with pytest.raises(AssertionError, match="write failed"):
            ib.write_image([ProgInfo(a, 0, 0x20)], tree.boot / "img", 0x100, 0)
