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
            port_def.setdefault("required_use", "")
            port_def.setdefault("desc", "")

            for field in ["requires", "conflicts"]:
                port_def.setdefault(field, [])

            yield (port_def, os.path.join("somedir", name))

    return closure


def build_get_ports_to_build(dct):
    def closure(ports_yamls):
        return dct

    return closure


def run_dry_build(all_ports, to_build, state_dir=None):
    pm = PortManager(
        [],
        get_ports_to_build=build_get_ports_to_build(to_build),
        find_ports=build_find_ports(all_ports),
        dry=True,
        ports_yamls="yaml1:yaml2",
        ports_dir="some_path",
        state_dir=str(state_dir) if state_dir else None,
    )
    pm.cmd_build()
    return pm


def test_port_resolution_simple(fix):
    all_ports = {"foo-1.2.3": {"requires": "bar>=1.1.1"}, "bar-2.0.0": {}}
    to_build = {"ports": [{"name": "foo"}]}
    run_dry_build(all_ports, to_build)


def test_port_resolution_conflicts_itself(fix):
    all_ports = {"foo-1.2.3": {"conflicts": "foo>=1.1.1"}}
    to_build = {"ports": [{"name": "foo"}]}

    with pytest.raises(ResolutionImpossible):
        run_dry_build(all_ports, to_build)


def test_port_resolution_conflicts_older_version(fix):
    all_ports = {"foo-1.2.3": {"conflicts": "foo!=1.2.3"}}
    to_build = {"ports": [{"name": "foo"}]}

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


def test_install_bad_env(fix, monkeypatch):
    with monkeypatch.context() as m:
        m.delenv("PREFIX_BUILD", raising=False)
        all_ports = {"foo-1.2.3": {"requires": "bar>=1.1.1"}, "bar-2.0.0": {}}
        to_build = {"ports": [{"name": "foo"}]}

        with pytest.raises(EnvironmentError) as ex:
            run_dry_build(all_ports, to_build)
        assert ex.value.args[0] == "PREFIX_BUILD undefined"

    with monkeypatch.context() as m:
        m.delenv("PREFIX_BUILD_VERSIONED", raising=False)

        all_ports = {
            "foo-1.2.3": {"requires": "bar>=1.1.1"},
            "bar-2.0.0": {"conflicts": "barng>=0.0"},
        }
        to_build = {"ports": [{"name": "foo"}]}
        with pytest.raises(EnvironmentError) as ex:
            run_dry_build(all_ports, to_build)
        assert ex.value.args[0] == "PREFIX_BUILD_VERSIONED undefined"


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


def test_ports_to_build_disable_bad_format(fix):
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1"},
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


def assert_ports_yaml_parsing(
    ports_yaml_contents: str, expected_dict: build_layer.PortsToBuildDict | None
):
    with tempfile.NamedTemporaryFile(mode="w+") as f:
        f.write(ports_yaml_contents)
        f.seek(0)
        assert build_layer.get_ports_to_build(f.name) == expected_dict


def dry_build_from_yaml(ports_yaml_contents, all_ports):
    with tempfile.NamedTemporaryFile(mode="w+") as f:
        f.write(ports_yaml_contents)
        f.seek(0)

        pm = PortManager(
            [],
            find_ports=build_find_ports(all_ports),
            dry=True,
            ports_yamls=f.name,
            ports_dir="some_path",
        )
        pm.cmd_build()
        return pm


def test_ports_yaml_jinja_bool_parsing(fix, monkeypatch):
    yaml = "var: {{ bool(env.VAR) }}"

    for true_str in ["y", "yes", "1", "true", "True"]:
        with monkeypatch.context() as m:
            m.setenv("VAR", true_str)
            assert_ports_yaml_parsing(yaml, {"var": True})

    for false_str in ["n", "no", "0", "false", "False"]:
        with monkeypatch.context() as m:
            m.setenv("VAR", false_str)
            assert_ports_yaml_parsing(yaml, {"var": False})

    # Undefined variable passed to bool() should default to false
    with monkeypatch.context() as m:
        m.delenv("VAR", raising=False)
        assert_ports_yaml_parsing(
            yaml,
            {"var": False},
        )


def test_ports_yaml_jinja_bool_parsing_build(fix, monkeypatch):
    all_ports = {
        "foo-1.2.3": {},
    }

    yaml = """
ports:
- name: foo
  if: {{ bool(env.BUILD_FOO) }}
"""

    for build_foo in ["y", "n"]:
        with monkeypatch.context() as m:
            m.setenv("BUILD_FOO", build_foo)
            pm = dry_build_from_yaml(yaml, all_ports)
            assert_version_mapping(pm, {"foo-1.2.3": {}} if build_foo == "y" else {})


def test_ports_yaml_should_fail_when_str_in_bool_fields(fix):
    all_ports = {
        "foo-1.2.3": {},
    }

    yamls = [
        """
        ports:
        - name: foo
          if: 'False'
        """,
        """
        tests: 'True'
        ports:
        - name: foo
        """,
        """
        ports:
        - name: foo
          tests: 'True'
        """,
    ]

    for yaml in yamls:
        with pytest.raises(SystemExit) as exc:
            dry_build_from_yaml(yaml, all_ports)
        assert exc.value.code == 1


def test_conditional_dep_flag_enabled(fix):
    """When the USE flag is enabled, the conditional dependency should be resolved."""
    all_ports = {
        "foo-1.2.3": {"requires": "ssl ? ( bar>=1.1.1 )", "iuse": "ssl"},
        "bar-2.0.0": {},
    }
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {"bar": "2.0.0"}})


def test_conditional_dep_flag_disabled(fix):
    """When the USE flag is not enabled, the conditional dependency should be skipped."""
    all_ports = {
        "foo-1.2.3": {"requires": "ssl ? ( bar>=1.1.1 )", "iuse": "ssl"},
        "bar-2.0.0": {},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {}})


def test_conditional_dep_missing_when_enabled(fix):
    """When the USE flag is enabled but the conditional dep is unavailable, resolution should fail."""
    all_ports = {
        "foo-1.2.3": {"requires": "ssl ? ( bar>=1.1.1 )", "iuse": "ssl"},
    }
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    with pytest.raises(ResolutionImpossible):
        run_dry_build(all_ports, to_build)


def test_use_flag_propagation(fix):
    """USE flags should be propagated to the dependency."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1[crypto]"},
        "bar-2.0.0": {"iuse": "crypto"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {"bar": "2.0.0"}})

    # Check that 'crypto' flag was propagated to bar
    bar_cand = pm.mapping["foo-1.2.3"]["bar"]
    assert "crypto" in bar_cand.use_flags


def test_use_flag_propagation_bad_flag(fix):
    """Propagating a USE flag not in the dependency's iuse should fail."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.1.1[nonexistent]"},
        "bar-2.0.0": {"iuse": "crypto"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_conditional_dep_with_use_propagation(fix):
    """Conditional dep with USE flag propagation: ssl ? ( bar>=1.1.1[crypto] )."""
    all_ports = {
        "foo-1.2.3": {"requires": "ssl ? ( bar>=1.1.1[crypto] )", "iuse": "ssl"},
        "bar-2.0.0": {"iuse": "crypto"},
    }
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {"bar": "2.0.0"}})

    bar_cand = pm.mapping["foo-1.2.3"]["bar"]
    assert "crypto" in bar_cand.use_flags


def test_conditional_dep_with_use_propagation_flag_disabled(fix):
    """When the condition flag is disabled, the dep (and its USE propagation) should be skipped."""
    all_ports = {
        "foo-1.2.3": {"requires": "ssl ? ( bar>=1.1.1[crypto] )", "iuse": "ssl"},
        "bar-2.0.0": {"iuse": "crypto"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {}})


def test_mixed_conditional_and_unconditional(fix):
    """Mix of conditional and unconditional deps in the same requires string."""
    all_ports = {
        "foo-1.2.3": {"requires": "baz>=1.0 ssl ? ( bar>=1.1.1 )", "iuse": "ssl"},
        "bar-2.0.0": {},
        "baz-1.5.0": {},
    }
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {"bar": "2.0.0", "baz": "1.5.0"}})

    # Without ssl flag
    to_build_no_ssl = {"ports": [{"name": "foo"}]}
    pm2 = run_dry_build(all_ports, to_build_no_ssl)
    assert_version_mapping(pm2, {"foo-1.2.3": {"baz": "1.5.0"}})


def test_use_flag_additive_propagation(fix):
    """foo requests bar[ssl], baz also depends on bar (no flags). ssl should still be set."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[ssl]"},
        "baz-1.0.0": {"requires": "bar>=1.0"},
        "bar-2.0.0": {"iuse": "ssl"},
    }
    to_build = {"ports": [{"name": "foo"}, {"name": "baz"}]}
    pm = run_dry_build(all_ports, to_build)

    bar_from_foo = pm.mapping["foo-1.2.3"]["bar"]
    assert "ssl" in bar_from_foo.use_flags


def test_required_use_at_most_one_conflict(fix):
    """?? ( x1 x2 ): foo requests bar[x1], baz requests bar[x2] -> error."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[x1]"},
        "baz-1.0.0": {"requires": "bar>=1.0[x2]"},
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "?? ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "foo"}, {"name": "baz"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_at_most_one_no_conflict(fix):
    """?? ( x1 x2 ): foo requests bar[x1], baz requests bar[x3] -> ok."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[x1]"},
        "baz-1.0.0": {"requires": "bar>=1.0[x3]"},
        "bar-2.0.0": {"iuse": "x1 x2 x3", "required_use": "?? ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "foo"}, {"name": "baz"}]}
    pm = run_dry_build(all_ports, to_build)

    bar_from_foo = pm.mapping["foo-1.2.3"]["bar"]
    assert "x1" in bar_from_foo.use_flags
    assert "x3" in bar_from_foo.use_flags


def test_required_use_at_most_one_none_set(fix):
    """?? ( x1 x2 ): no flags set -> ok (zero is fine)."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0"},
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "?? ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)
    assert_version_mapping(pm, {"foo-1.2.3": {"bar": "2.0.0"}})


def test_required_use_exactly_one(fix):
    """^^ ( x1 x2 ): exactly one must be set."""
    all_ports = {
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "^^ ( x1 x2 )"},
    }
    # One set -> ok
    to_build = {"ports": [{"name": "bar", "use": ["x1"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert "x1" in pm.mapping["bar-2.0.0"]["bar"].use_flags


def test_required_use_exactly_one_none(fix):
    """^^ ( x1 x2 ): none set -> error."""
    all_ports = {
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "^^ ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "bar"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_exactly_one_both(fix):
    """^^ ( x1 x2 ): both set -> error."""
    all_ports = {
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "^^ ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "bar", "use": ["x1", "x2"]}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_any_of(fix):
    """|| ( x1 x2 ): at least one must be set."""
    all_ports = {
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "|| ( x1 x2 )"},
    }
    # One set -> ok
    to_build = {"ports": [{"name": "bar", "use": ["x2"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert "x2" in pm.mapping["bar-2.0.0"]["bar"].use_flags

    # Both set -> also ok
    to_build_both = {"ports": [{"name": "bar", "use": ["x1", "x2"]}]}
    pm2 = run_dry_build(all_ports, to_build_both)
    assert "x1" in pm2.mapping["bar-2.0.0"]["bar"].use_flags


def test_required_use_any_of_none(fix):
    """|| ( x1 x2 ): none set -> error."""
    all_ports = {
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "|| ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "bar"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_conditional_positive(fix):
    """ssl? ( crypto ): if ssl is set, crypto must be set."""
    all_ports = {
        "bar-2.0.0": {"iuse": "ssl crypto", "required_use": "ssl? ( crypto )"},
    }
    # ssl + crypto -> ok
    to_build = {"ports": [{"name": "bar", "use": ["ssl", "crypto"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert "ssl" in pm.mapping["bar-2.0.0"]["bar"].use_flags
    assert "crypto" in pm.mapping["bar-2.0.0"]["bar"].use_flags

    # no ssl -> ok (constraint doesn't apply)
    to_build2 = {"ports": [{"name": "bar"}]}
    run_dry_build(all_ports, to_build2)


def test_required_use_conditional_positive_violated(fix):
    """ssl? ( crypto ): ssl set but crypto not -> error."""
    all_ports = {
        "bar-2.0.0": {"iuse": "ssl crypto", "required_use": "ssl? ( crypto )"},
    }
    to_build = {"ports": [{"name": "bar", "use": ["ssl"]}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_conditional_negated(fix):
    """!minimal? ( extras ): if minimal is NOT set, extras must be set."""
    all_ports = {
        "bar-2.0.0": {"iuse": "minimal extras", "required_use": "!minimal? ( extras )"},
    }
    # minimal not set, extras set -> ok
    to_build = {"ports": [{"name": "bar", "use": ["extras"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert "extras" in pm.mapping["bar-2.0.0"]["bar"].use_flags

    # minimal set -> ok (constraint doesn't apply)
    to_build2 = {"ports": [{"name": "bar", "use": ["minimal"]}]}
    run_dry_build(all_ports, to_build2)


def test_required_use_conditional_negated_violated(fix):
    """!minimal? ( extras ): minimal NOT set, extras NOT set -> error."""
    all_ports = {
        "bar-2.0.0": {"iuse": "minimal extras", "required_use": "!minimal? ( extras )"},
    }
    to_build = {"ports": [{"name": "bar"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_required_use_conditional_negative_child(fix):
    """ssl? ( !gnutls ): if ssl is set, gnutls must be disabled."""
    all_ports = {
        "bar-2.0.0": {"iuse": "ssl gnutls", "required_use": "ssl? ( !gnutls )"},
    }
    # ssl without gnutls -> ok
    to_build = {"ports": [{"name": "bar", "use": ["ssl"]}]}
    pm = run_dry_build(all_ports, to_build)
    assert "ssl" in pm.mapping["bar-2.0.0"]["bar"].use_flags

    # ssl with gnutls -> error
    to_build2 = {"ports": [{"name": "bar", "use": ["ssl", "gnutls"]}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build2)


def test_required_use_multiple_exprs(fix):
    """Multiple expressions: ^^ ( a b ) ssl? ( crypto )."""
    all_ports = {
        "bar-2.0.0": {
            "iuse": "a b ssl crypto",
            "required_use": "^^ ( a b ) ssl? ( crypto )",
        },
    }
    # a set, ssl+crypto -> ok
    to_build = {"ports": [{"name": "bar", "use": ["a", "ssl", "crypto"]}]}
    pm = run_dry_build(all_ports, to_build)
    bar = pm.mapping["bar-2.0.0"]["bar"]
    assert set(bar.use_flags) == {"a", "ssl", "crypto"}

    # a set, no ssl -> ok (conditional doesn't apply)
    to_build2 = {"ports": [{"name": "bar", "use": ["b"]}]}
    run_dry_build(all_ports, to_build2)

    # both a and b set -> error (^^ violated)
    to_build3 = {"ports": [{"name": "bar", "use": ["a", "b"]}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build3)

    # a set, ssl without crypto -> error (conditional violated)
    to_build4 = {"ports": [{"name": "bar", "use": ["a", "ssl"]}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build4)


def test_required_use_propagation_conflict(fix):
    """Propagated flags must also satisfy the dep's REQUIRED_USE.
    foo->bar[x1], baz->bar[x2], bar has ?? ( x1 x2 ) -> error."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[x1]"},
        "baz-1.0.0": {"requires": "bar>=1.0[x2]"},
        "bar-2.0.0": {"iuse": "x1 x2", "required_use": "?? ( x1 x2 )"},
    }
    to_build = {"ports": [{"name": "foo"}, {"name": "baz"}]}
    with pytest.raises(SystemExit):
        run_dry_build(all_ports, to_build)


def test_use_flag_origin_tracking(fix):
    """USE flag origins should be recorded for traceability."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[crypto]"},
        "bar-2.0.0": {"iuse": "crypto"},
    }
    to_build = {"ports": [{"name": "foo"}]}
    pm = run_dry_build(all_ports, to_build)

    bar_cand = pm.mapping["foo-1.2.3"]["bar"]
    assert "crypto" in bar_cand.use_flags
    assert "crypto" in bar_cand.use_flags_origins
    assert "foo-1.2.3" in bar_cand.use_flags_origins["crypto"]


def test_use_flag_origin_user(fix):
    """Flags set in ports.yaml should have origin 'user'."""
    all_ports = {
        "foo-1.2.3": {"iuse": "debug"},
    }
    to_build = {"ports": [{"name": "foo", "use": ["debug"]}]}
    pm = run_dry_build(all_ports, to_build)

    foo_cand = pm.mapping["foo-1.2.3"]["foo"]
    assert "debug" in foo_cand.use_flags
    assert "user" in foo_cand.use_flags_origins["debug"]


def test_use_flag_multiple_origins(fix):
    """When both user and a parent propagate the same flag, both origins should be recorded."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[ssl]"},
        "baz-1.0.0": {"requires": "bar>=1.0[ssl]"},
        "bar-2.0.0": {"iuse": "ssl"},
    }
    to_build = {"ports": [{"name": "foo"}, {"name": "baz"}]}
    pm = run_dry_build(all_ports, to_build)

    bar_from_foo = pm.mapping["foo-1.2.3"]["bar"]
    assert "ssl" in bar_from_foo.use_flags
    assert "foo-1.2.3" in bar_from_foo.use_flags_origins["ssl"]
    assert "baz-1.0.0" in bar_from_foo.use_flags_origins["ssl"]


def test_build_state_saved(fix, tmp_path):
    """After a dry build with state_dir, state files should be written."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl"}}
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    run_dry_build(all_ports, to_build, state_dir=tmp_path)

    state_file = tmp_path / "foo-1.2.3.json"
    assert state_file.exists()

    import json

    state = json.loads(state_file.read_text())
    assert state == {"use_flags": ["ssl"], "tests": False}


def test_no_stale_when_flags_unchanged(fix, tmp_path):
    """Second build with same flags should detect no stale ports."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl"}}
    to_build = {"ports": [{"name": "foo", "use": ["ssl"]}]}
    run_dry_build(all_ports, to_build, state_dir=tmp_path)

    pm = run_dry_build(all_ports, to_build, state_dir=tmp_path)
    assert not pm.stale_ports


def test_stale_on_flag_add(fix, tmp_path):
    """Adding a USE flag should mark the port as stale."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl crypto"}}

    run_dry_build(all_ports, {"ports": [{"name": "foo", "use": ["ssl"]}]}, state_dir=tmp_path)
    pm = run_dry_build(
        all_ports, {"ports": [{"name": "foo", "use": ["ssl", "crypto"]}]}, state_dir=tmp_path
    )
    assert "foo-1.2.3" in pm.stale_ports


def test_stale_on_flag_remove(fix, tmp_path):
    """Removing a USE flag should mark the port as stale."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl crypto"}}

    run_dry_build(
        all_ports, {"ports": [{"name": "foo", "use": ["ssl", "crypto"]}]}, state_dir=tmp_path
    )
    pm = run_dry_build(
        all_ports, {"ports": [{"name": "foo", "use": ["ssl"]}]}, state_dir=tmp_path
    )
    assert "foo-1.2.3" in pm.stale_ports


def test_stale_propagates_to_dependents(fix, tmp_path):
    """If a dep's flags change, all ports depending on it are also stale."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0"},
        "bar-2.0.0": {"iuse": "ssl"},
    }

    run_dry_build(
        all_ports, {"ports": [{"name": "foo"}, {"name": "bar", "use": ["ssl"]}]},
        state_dir=tmp_path,
    )
    pm = run_dry_build(
        all_ports, {"ports": [{"name": "foo"}, {"name": "bar"}]},
        state_dir=tmp_path,
    )
    # bar changed (ssl removed), foo depends on bar -> both stale
    assert "bar-2.0.0" in pm.stale_ports
    assert "foo-1.2.3" in pm.stale_ports


def test_stale_state_file_updated_after_rebuild(fix, tmp_path):
    """After a stale port is rebuilt, its state file should reflect the new flags."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl crypto"}}

    run_dry_build(all_ports, {"ports": [{"name": "foo", "use": ["ssl"]}]}, state_dir=tmp_path)
    run_dry_build(
        all_ports, {"ports": [{"name": "foo", "use": ["ssl", "crypto"]}]}, state_dir=tmp_path
    )

    import json

    state = json.loads((tmp_path / "foo-1.2.3.json").read_text())
    assert state == {"use_flags": ["crypto", "ssl"], "tests": False}


def test_stale_via_propagated_flags(fix, tmp_path):
    """Propagated flag change triggers stale detection."""
    all_ports = {
        "foo-1.2.3": {"requires": "bar>=1.0[ssl]"},
        "bar-2.0.0": {"iuse": "ssl crypto"},
    }
    run_dry_build(all_ports, {"ports": [{"name": "foo"}]}, state_dir=tmp_path)

    # Now foo propagates both ssl and crypto
    all_ports2 = {
        "foo-1.2.3": {"requires": "bar>=1.0[ssl,crypto]"},
        "bar-2.0.0": {"iuse": "ssl crypto"},
    }
    pm = run_dry_build(all_ports2, {"ports": [{"name": "foo"}]}, state_dir=tmp_path)

    # bar's flags changed (gained crypto) -> bar and foo are stale
    assert "bar-2.0.0" in pm.stale_ports
    assert "foo-1.2.3" in pm.stale_ports


def test_first_build_no_stale(fix, tmp_path):
    """First build (no saved state) should not mark anything as stale."""
    all_ports = {"foo-1.2.3": {"iuse": "ssl"}}
    pm = run_dry_build(all_ports, {"ports": [{"name": "foo", "use": ["ssl"]}]}, state_dir=tmp_path)
    assert not pm.stale_ports


def test_stale_on_tests_flag_change(fix, tmp_path):
    """Changing the tests flag should also trigger a rebuild."""
    all_ports = {"foo-1.2.3": {}}

    run_dry_build(all_ports, {"ports": [{"name": "foo"}]}, state_dir=tmp_path)
    pm = run_dry_build(
        all_ports, {"ports": [{"name": "foo", "tests": True}]}, state_dir=tmp_path
    )
    assert "foo-1.2.3" in pm.stale_ports
