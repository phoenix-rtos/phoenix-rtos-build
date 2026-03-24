#
# Port management
#
# Tests for port builder with dependency resolution
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
import os
import tempfile

from resolvelib.resolvers import (
    ResolutionImpossible,
    ResolutionTooDeep,
)
from port_manager.port_manager import PortManager
from port_manager.version import PhxVersion
from port_manager.logger import LogLevel, logger
from port_manager import build_layer

PREFIX_BUILD = "normal_port_install_dir"
PREFIX_BUILD_VERSIONED = "versioned_port_install_dir"
PREFIX_PORTS = "ports"
PHOENIX_VER = "v3.3.1"


@pytest.fixture(scope="session")
def fix():
    os.environ["PHOENIX_VER"] = PHOENIX_VER
    os.environ["PREFIX_BUILD"] = PREFIX_BUILD
    os.environ["PREFIX_BUILD_VERSIONED"] = PREFIX_BUILD_VERSIONED
    logger.set_level(LogLevel.VERBOSE if os.getenv("V", "0") == "1" else LogLevel.NONE)
    yield


def build_find_ports(dct):
    def closure(ports_dir):
        for name, port_def in dct.items():
            port_def["namever"] = name

            port_def.setdefault("supports", "phoenix>=3.3")
            port_def.setdefault("iuse", "")
            port_def.setdefault("desc", "")

            for field in ["requires", "optional", "conflicts"]:
                port_def.setdefault(field, [])

            yield (port_def, os.path.join("somedir", name))

    return closure


def build_get_ports_to_build(dct):
    def closure(port_yamls):
        return dct

    return closure


def run_dry_build(all_ports, to_build):
    pm = PortManager(
        [],
        get_ports_to_build=build_get_ports_to_build(to_build),
        find_ports=build_find_ports(all_ports),
        dry=True,
        ports_yamls="yaml1:yaml2",
        ports_dir="some_path",
    )
    pm.cmd_build()
    return pm


def test_port_resolution_simple(fix):
    all_ports = {"foo-1.2.3": {"requires": "bar>=1.1.1"}, "bar-2.0.0": {}}
    to_build = {"ports": [{"name": "foo"}]}
    run_dry_build(all_ports, to_build)


def test_port_resolution_depends_optional(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1", "optional": "baz>=3.2.1"},
        "bar-2.0.0": {},
    }
    to_build = {"ports": [{"name": "foo"}]}
    run_dry_build(all_ports, to_build)

    all_ports["baz-3.2.1"] = {}
    run_dry_build(all_ports, to_build)


def test_port_resolution_conflicts_itself(fix):
    all_ports = {"foo-1.2.3": {"conflicts": "foo>=1.1.1"}}
    to_build = {"ports": [{"name": "foo"}]}

    with pytest.raises(ResolutionImpossible):
        run_dry_build(all_ports, to_build)


def assert_version_mapping(pm, port_mappings, phoenix_ver=PHOENIX_VER):
    deps_to_install = 0

    for namever, exp_mappings in port_mappings.items():
        name, ver = namever.split("-")
        resolved_mapping = pm.mapping[namever]

        # +2: one cand is phoenix, one is the target port itself
        assert len(resolved_mapping) == len(exp_mappings) + 2

        assert resolved_mapping["phoenix"].version == PhxVersion(phoenix_ver)
        assert resolved_mapping[name].version == PhxVersion(ver)

        for dep_name, ver in exp_mappings.items():
            assert resolved_mapping[dep_name].version == PhxVersion(ver)

        deps_to_install += len(exp_mappings)

    # number of deps + number of keys (user-defined ports)
    assert len(pm.ports_installed) == deps_to_install + len(port_mappings)

    # TODO: explicit installed ports check


def test_port_resolution_independent_conflicts_simple(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
        "barng-2.2.0": {"conflicts": "bar>=0.0"},
        "baz-3.2.0": {"requires": "barng>=1.1.1"},
    }

    to_build = {
        "ports": [
            {"name": "foo", "version": "1.2.3"},
            {"name": "baz", "version": "3.2.0"},
        ]
    }
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(
        pm, {"foo-1.2.3": {"bar": "2.0.0"}, "baz-3.2.0": {"barng": "2.2.0"}}
    )


def test_port_resolution_independent_conflicts_alternative(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
        "barng-2.2.0": {"conflicts": "bar>=0.0"},
        "foo-3.2.0": {"requires": "barng>=1.1.1"},
        "baz-1.1.1": {"requires": "foo>=1.1.1"},
        "raz-1.1.1": {"requires": "foo==1.2.3"},
    }

    to_build = {"ports": [{"name": "baz"}, {"name": "raz"}]}
    pm = run_dry_build(all_ports, to_build)

    # Resolver should pick alternative with newest version
    assert_version_mapping(
        pm,
        {
            "baz-1.1.1": {"foo": "3.2.0", "barng": "2.2.0"},
            "raz-1.1.1": {"foo": "1.2.3", "bar": "2.0.0"},
        },
    )


def test_port_resolution_independent_conflicts_choose_alternative(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
        "barng-2.2.0": {"conflicts": "bar>=0.0"},
        "foo-3.2.0": {"requires": "barng>=1.1.1"},
        "baz-1.1.1": {"requires": "foo>=1.1.1"},
    }

    to_build = {"ports": [{"name": "baz"}]}
    pm = run_dry_build(all_ports, to_build)

    # Resolver should pick alternative with newest version
    assert_version_mapping(pm, {"baz-1.1.1": {"foo": "3.2.0", "barng": "2.2.0"}})


def test_resolution_conflicting_port_dependencies(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
        "barng-2.2.0": {"conflicts": "bar>=0.0"},
        "baz-3.2.0": {"requires": "barng>=1.1.1"},
        "faz-4.2.0": {"requires": "foo>=1.0 baz>=1.0"},
    }

    to_build = {"ports": [{"name": "faz"}]}

    with pytest.raises(ResolutionTooDeep):
        run_dry_build(all_ports, to_build)


def test_resolution_unsatisfiable_simple(fix):
    all_ports = {"foo-1.2.3": {"requires": "bar>=1.1.1"}}

    to_build = {"ports": [{"name": "foo"}]}

    with pytest.raises(ResolutionImpossible):
        run_dry_build(all_ports, to_build)


def test_resolution_unsatisfiable_version(fix):
    unsatisfiable_bar_requires = [
        "bar>=3.1.1",
        "bar<2.0.1",
        "bar<=2.0.0",
        "bar>2.0.1",
        "bar>=2.0.2",
        "bar==2.0.10",
    ]

    for req in unsatisfiable_bar_requires:
        all_ports = {
            "foo-1.2.3": {"requires": req},
            "bar-2.0.1": {},
        }

        to_build = {"ports": [{"name": "foo"}]}

        with pytest.raises(ResolutionImpossible):
            run_dry_build(all_ports, to_build)


def test_install_path(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)

    assert PREFIX_BUILD == pm.mapping["foo-1.2.3"]["foo"].install_path
    assert (
        os.path.join(PREFIX_BUILD_VERSIONED, "bar-2.0.0")
        == pm.mapping["foo-1.2.3"]["bar"].install_path
    )


def test_install_bad_env(fix):
    del os.environ["PREFIX_BUILD"]

    all_ports = {"foo-1.2.3": {"requires": "bar>=1.1.1"}, "bar-2.0.0": {}}
    to_build = {"ports": [{"name": "foo"}]}

    with pytest.raises(EnvironmentError) as ex:
        run_dry_build(all_ports, to_build)
    assert ex.value.args[0] == "PREFIX_BUILD undefined"

    os.environ["PREFIX_BUILD"] = PREFIX_BUILD

    del os.environ["PREFIX_BUILD_VERSIONED"]

    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {"conflicts": "barng>=0.0"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    with pytest.raises(EnvironmentError) as ex:
        run_dry_build(all_ports, to_build)
    assert ex.value.args[0] == "PREFIX_BUILD_VERSIONED undefined"

    os.environ["PREFIX_BUILD_VERSIONED"] = PREFIX_BUILD_VERSIONED


def test_ports_to_build_override(fix):
    all_ports = {
        "foo-1.2.3": {},
    }
    to_build = {
        "ports": [
            {"name": "foo"},
            {"name": "foo", "if": False},
        ]
    }

    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {})


def test_ports_to_build_short_name(fix):
    all_ports = {
        "foo-1.2.3": {},
    }
    to_build = {
        "ports": [
            "foo",
        ],
    }

    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {}})


def test_ports_to_build_disabled_ports(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {},
    }
    to_build = {
        "ports": [
            {"name": "foo"},
            {"name": "foo", "version": "1.2.3"},
        ],
        "disabled-ports": [
            "foo",
        ],
    }

    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {})


def test_ports_to_build_disable_required_dependency(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
        "bar-2.0.0": {},
    }
    to_build = {
        "ports": [
            {"name": "foo"},
        ],
        "disabled-ports": [
            "bar",
        ],
    }

    with pytest.raises(ResolutionImpossible):
        run_dry_build(all_ports, to_build)


def test_ports_to_build_disable_optional_dependency(fix):
    all_ports = {
        "foo-1.2.3": {"optional": "bar>=1.1.1"},
        "bar-2.0.0": {},
    }
    to_build = {
        "ports": [
            {"name": "foo"},
        ],
        "disabled-ports": [
            "bar",
        ],
    }

    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {}})


def test_ports_to_build_disable_bad_format(fix):
    all_ports = {
        "foo-1.2.3": {"optional": "bar>=1.1.1"},
        "bar-2.0.0": {},
    }

    for bad_format in [True, "string", [["bar"], ["foo"]]]:
        to_build = {
            "ports": [
                {"name": "foo"},
            ],
            "disabled-ports": bad_format,
        }
        with pytest.raises(SystemExit) as exc:
            run_dry_build(all_ports, to_build)
        assert exc.value.code == 1


def assert_port_yaml_parsing(
    port_yaml_contents: str, expected_dict: build_layer.PortsToBuildDict | None
):
    with tempfile.NamedTemporaryFile(mode="w+") as f:
        f.write(port_yaml_contents)
        f.seek(0)
        assert build_layer.get_ports_to_build(f.name) == expected_dict


def test_port_yaml_jinja_bool_parsing(fix, monkeypatch):
    yaml = "var: {{ bool(env.VAR) }}"

    for true_str in ["y", "yes", "1", "true", "True"]:
        with monkeypatch.context() as m:
            m.setenv("VAR", true_str)
            assert_port_yaml_parsing(yaml, {"var": True})

    for false_str in ["n", "no", "0", "false", "False"]:
        with monkeypatch.context() as m:
            m.setenv("VAR", false_str)
            assert_port_yaml_parsing(yaml, {"var": False})

    # Undefined variable passed to bool() should default to false
    with monkeypatch.context() as m:
        m.delenv("VAR", raising=False)
        assert_port_yaml_parsing(
            yaml,
            {"var": False},
        )
