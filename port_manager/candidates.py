#!/usr/bin/env python3
#
# Port management
#
# Resolver candidate types
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from collections.abc import Iterable, Generator, Collection

import os
import time
import sys

from pathlib import Path
from enum import IntEnum

from build_core.logger import logger

from .requirements import ConflictRequirement, ConditionalRequirement, Requirement
from .required_use import RequiredUseExpr, validate_required_use
from .version import PhxVersion
from . import build_layer


class DryMode(IntEnum):
    OFF = 0
    UNPACK = 1
    FULL_DRY = 2


class Candidate:
    """Class used by the resolver to satisfy the input requirements"""

    def __init__(
        self,
        name: str,
        version: PhxVersion,
        requirements: Iterable[Requirement],
        conflicts: Iterable[ConflictRequirement],
        exposed_use_flags: list[str],
        desc: str,
        required_use: list[RequiredUseExpr] | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self._requirements = requirements
        self._conflicts = conflicts
        self.exposed_use_flags = exposed_use_flags
        self.use_flags: list[str] = []
        self.use_flags_origins: dict[str, list[str]] = {}
        self.required_use: list[RequiredUseExpr] = required_use or []
        self.desc = desc

    def __repr__(self) -> str:
        return f"{self.name}-{self.version}"

    def set_use_flags(self, flags: Collection[str], origin: str = "user") -> None:
        diff = list(set(flags) - set(self.exposed_use_flags))
        if diff:
            logger.error(f"unrecognized flags for {self}:", diff)
            sys.exit(1)

        new_flags = set(self.use_flags) | set(flags)

        valid, err = validate_required_use(self.required_use, new_flags)
        if not valid:
            # Build origin trace for the conflicting flags
            origins = dict(self.use_flags_origins)
            for f in flags:
                origins.setdefault(f, [])
                if origin not in origins[f]:
                    origins[f].append(origin)
            trace = ", ".join(
                f"+{f} (by {', '.join(o)})" for f, o in sorted(origins.items()) if f in new_flags
            )
            logger.error(f"REQUIRED_USE violated on {self}: {err}\n  Flag origins: {trace}")
            sys.exit(1)

        self.use_flags = list(new_flags)

        for flag in flags:
            if flag not in self.use_flags_origins:
                self.use_flags_origins[flag] = []
            if origin not in self.use_flags_origins[flag]:
                self.use_flags_origins[flag].append(origin)

    def iter_dependencies(self) -> Iterable[Requirement]:
        """Returns an iterable with requirements that model the required
        dependencies of the candidate. The iterable will contain
        a ConditionalRequirement only if the candidate has enabled
        the corresponding flag."""
        return (
            r for r in self._requirements
            if not isinstance(r, ConditionalRequirement) or r.use_flag in self.use_flags
        )

    def iter_conflicts(self) -> Iterable[ConflictRequirement]:
        return self._conflicts

    def conflicts_with(self, candidate: Candidate) -> bool:
        for creq in self._conflicts:
            if creq.is_satisfied_by(candidate):
                return True
        return False

    def to_dict(self, ports_dir: str) -> dict[str, str | list | dict]:
        return {
            "version": str(self.version),
            "requirements": [str(r) for r in self._requirements],
            "conflicts": [str(r) for r in self.iter_conflicts()],
            "required_use": [str(ru) for ru in self.required_use],
            "iuse": self.exposed_use_flags,
            "desc": self.desc,
        }

    def iter_installable_dep_cands(
        self, mapping: dict[str, Candidate]
    ) -> Generator[InstallableCandidate]:
        for dep in self.iter_dependencies():
            assert dep.name in mapping, "mapping should be a superset of iter_dependencies()"
            cand = mapping[dep.name]
            if not isinstance(cand, InstallableCandidate):
                continue
            yield cand

    def install(
        self,
        mapping: dict[str, Candidate],
        dep_of: Candidate | None = None,
        **kwargs,
    ) -> None:
        pass


class OsCandidate(Candidate):
    """
    A meta-candidate used for expressing the port requirement for specific
    OS version, e.g. "phoenix>=3.2"
    """

    def __init__(self, name: str, version: PhxVersion) -> None:
        super().__init__(name, version, [], [], [], "", required_use=[])

    def __repr__(self) -> str:
        return f"OS:{self.name}-{self.version}"


class InstallableCandidate(Candidate):
    """
    A candidate that is installable either to PREFIX_BUILD or
    PREFIX_BUILD_VERSIONED (e.g. ports defined by a port.def.sh)
    """

    def __init__(
        self,
        *args,
        definition_path: str,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.needed_by: list[Candidate] = []
        self.installed = False
        self.build_tests = False
        self.user_required = False

        self.definition_path = definition_path

    @property
    def install_path(self) -> str:
        if self._conflicts:
            # If port is conflictable, it has a special installation directory
            prefix = os.environ["PREFIX_BUILD_VERSIONED"]
            return os.path.join(prefix, f"{self.name}-{str(self.version)}")
        else:
            # Otherwise, it is treated like normal libs
            prefix = os.environ["PREFIX_BUILD"]
            return f"{prefix}"

    def install(
        self,
        mapping: dict[str, Candidate],
        dep_of: Candidate | None = None,
        **kwargs,
    ) -> None:
        # Validate REQUIRED_USE before installing (set_use_flags may not be called)
        valid, err = validate_required_use(self.required_use, set(self.use_flags))
        if not valid:
            logger.error(f"REQUIRED_USE violated on {self}: {err}")
            sys.exit(1)

        dry = kwargs.get("dry", DryMode.OFF)
        roll_logs = kwargs.get("roll_logs", False)

        info = f"{self}"
        extras_info = []

        port_env = os.environ.copy()

        if dep_of:
            extras_info.append(f"dependency of {dep_of}")

        if len(self.use_flags) > 0:
            for use_flag in self.use_flags:
                port_env[f"PORT_USE_{use_flag}"] = "y"

            extras_info.append("+USE flags: " + " ".join(self.use_flags))

        if self.build_tests:
            port_env["PORT_BUILD_TESTS"] = "y"

            extras_info.append("+tests")

        if len(extras_info) > 0:
            info += f" ({', '.join(extras_info)})"

        logger.info(info)

        logger.nest(self.name)

        if self.installed:
            logger.info("Already installed")
            logger.unnest()
            return

        start = time.time()

        port_env["PREFIX_PORT_INSTALL"] = self.install_path

        deps_info_emitted = False

        for dep_cand in self.iter_installable_dep_cands(mapping):
            if not deps_info_emitted:
                logger.info("-> Build deps")
                deps_info_emitted = True

            dep_cand.install(mapping, dep_of=self, **kwargs)
            dep_cand.needed_by.append(self)

        lib_path_set = set()
        pkg_config_path_set = set()
        for dep_cand in self.iter_installable_dep_cands(mapping):
            env_name = f"PORT_DEP_{dep_cand.name}"
            if dep_cand.installed:
                install_path = dep_cand.install_path
                port_env[env_name] = install_path
                lib_path = os.path.join(install_path, "lib")
                pkg_config_path_set.add(os.path.join(lib_path, "pkgconfig"))
                lib_path_set.add("-L" + lib_path)
            else:
                port_env[env_name] = ""

            logger.debug(
                env_name,
                dep_cand.install_path if dep_cand.installed else "<empty>",
            )

        if dry == DryMode.OFF or dry == DryMode.UNPACK:
            port_env["PKG_CONFIG_PATH"] = ":".join(list(pkg_config_path_set))

            # export dependency lib directories as a fallback variable to be
            # available in case pkg-config/autoconf misbehaves
            port_env["PORT_DEP_LDFLAGS"] = " " + " ".join(list(lib_path_set))

            port_env = build_layer.prepare_cand(self, port_env, roll_logs)

        if dry == DryMode.OFF:
            build_layer.build_cand(self, port_env, roll_logs)

        stop = time.time()
        logger.info(f"Installed ({stop - start:.2f} s)", end_tree=True)

        logger.unnest()

        self.installed = True

        if "ports_installed" in kwargs:
            kwargs["ports_installed"].append(self)

    def to_dict(self, ports_dir: str) -> dict[str, str | list | dict]:
        return super().to_dict(ports_dir) | {
            "port_def_path": str(Path(self.definition_path).relative_to(ports_dir)),
        }
