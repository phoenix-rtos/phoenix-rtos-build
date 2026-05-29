#!/usr/bin/env python3
#
# Port management
#
# Port builder with dependency resolution
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from typing import Any, TypeVar
from collections.abc import Callable
from collections.abc import Sequence, Generator

import sys
import time
import json
import os

from pathlib import Path

from argparse import Namespace, ArgumentParser, RawDescriptionHelpFormatter

from .version import PhxVersion, PhxVersionGrammar
from .logger import logger, LogLevel
from .requirements import (
    BaseRequirement,
    ConflictRequirement,
    ConditionalRequirement,
    Constraint,
)
from .candidates import Candidate, OsCandidate, InstallableCandidate
from .resolver import PhxResolver, CandidatesDict
from .required_use import parse_required_use
from . import build_layer

T = TypeVar("T")


def parse_requirements(s: str, req_constructor: Callable[[str, list[Constraint]], T]) -> list[T]:
    requirements_objects = []
    if s:
        for elem in PhxVersionGrammar.parse_string(s):
            if "cond_flag" in elem:
                cond_flag = elem.cond_flag
                for dep in elem.cond_deps:
                    flags = list(dep.use_flags)
                    requirements_objects.append(
                        ConditionalRequirement(dep[0], [(dep[1], dep[2])], cond_flag, flags)
                    )
            else:
                flags = list(elem.use_flags)
                req = req_constructor(elem[0], [(elem[1], elem[2])])
                req.propagated_use_flags = flags
                requirements_objects.append(req)

    return requirements_objects


def parse_namever(namever: str) -> Constraint:
    elems = namever.split("-")
    if len(elems) != 2:
        raise ValueError(f"bad name-ver - expected NAME-VERSION, got '{namever}'")
    return (elems[0], PhxVersion(elems[1]))


def require_bool(dct: dict[str, Any], key: str, default: bool) -> bool:
    val = dct.get(key, default)
    if not isinstance(val, bool):
        logger.error(f"'{key}' should be bool but got {val} ({val.__class__})")
        sys.exit(1)
    return val


class PortManager:
    def __init__(
        self,
        argv: Sequence[str],
        dry: bool = False,
        ports_dir: str | None = None,
        ports_yamls: str | None = None,
        find_ports: Callable[[str], Generator[tuple[dict[str, str], Path]]]
        | None = None,
        get_ports_to_build: Callable[[str], build_layer.PortsToBuildDict | None]
        | None = None,
        state_dir: str | None = None,
    ) -> None:
        self.discovered_ports: CandidatesDict = dict()
        self.os_candidates_added = False

        self.mapping: CandidatesDict = dict()
        self.roll_logs = False
        self.build_all = False
        self.dry = dry  # self.dry may be overwritten by _parse_arguments
        self.args = self._parse_arguments(argv)

        self.os_candidates_added = False

        # overrides allowed purely for pytest testing (when self.args is empty)
        if ports_dir:
            self.args.ports_dir = ports_dir
        if ports_yamls:
            self.args.ports_yamls = ports_yamls
        self.get_ports_to_build = (
            get_ports_to_build if get_ports_to_build else build_layer.get_ports_to_build
        )
        self.find_ports = find_ports if find_ports else build_layer.find_ports

        self.ports_installed: list[Candidate] = []
        self.ports_skipped: list[str] = []
        self._state_dir = Path(state_dir) if state_dir else None
        self.stale_ports: set[str] = set()

    def add_candidate(self, candidate: Candidate) -> None:
        name = candidate.name
        version = str(candidate.version)
        if name not in self.discovered_ports:
            self.discovered_ports[name] = dict()

        self.discovered_ports[name][version] = candidate

        logger.debug(f"added {candidate} reqs={list(candidate.iter_dependencies())}")

    def add_os_candidates(self) -> None:
        """
        Adds dummy OS candidates that provide the resolver with OS versions
        to satisfy `supports` requirements.
        """
        if not self.os_candidates_added:
            # ignore any abbrevs that may possibly be emitted if version is taken with `git describe`
            phoenix_ver = os.environ["PHOENIX_VER"].split("-", 1)[0]

            self.add_candidate(OsCandidate("phoenix", PhxVersion(phoenix_ver)))
            self.add_candidate(OsCandidate("host", PhxVersion("0")))
            self.os_candidates_added = True

    def discover_ports(self):
        for port, def_path in self.find_ports(self.args.ports_dir):
            name, version = parse_namever(port["namever"])

            req = parse_requirements(port["requires"], BaseRequirement)
            req += parse_requirements(port["supports"], BaseRequirement)

            conflicts = parse_requirements(
                port["conflicts"],
                lambda r, c: ConflictRequirement(name, r, c),
            )

            if not def_path:
                raise ValueError("Empty definition path")

            available_flags = port["iuse"].split()

            # Parse REQUIRED_USE: Gentoo-like USE flag constraint expressions
            # e.g. "^^ ( x1 x2 )" or "ssl? ( crypto )" or "?? ( a b c )"
            required_use_str = port.get("required_use", "")
            required_use_exprs = parse_required_use(required_use_str)

            self.add_candidate(
                InstallableCandidate(
                    name,
                    version,
                    req,
                    conflicts,
                    str(def_path),
                    available_flags,
                    port["desc"],
                    required_use=required_use_exprs,
                )
            )

    def propagate_use_flags(self) -> None:
        """Propagate USE flags from requirements to dependency candidates.

        Iterates to a fixed point since newly propagated flags may activate
        conditional dependencies that carry further propagations."""
        changed = True
        while changed:
            # WARN: For now, the flag state is monotonic, so the fixed point is
            # always reachable. This won't be the case once the flag negations
            # (or any other monotonicity-breaking feature) are implemented.
            changed = False
            for mapping in self.mapping.values():
                for cand in mapping.values():
                    for req in cand.iter_dependencies():
                        if not req.propagated_use_flags:
                            continue
                        if req.name not in mapping:
                            continue
                        dep_cand = mapping[req.name]
                        new_flags = set(req.propagated_use_flags) - set(dep_cand.use_flags)
                        dep_cand.set_use_flags(req.propagated_use_flags, origin=str(cand))
                        if new_flags:
                            changed = True

    def resolve_propagated_deps(self) -> None:
        """Re-resolve mappings until all propagation-activated deps are present.

        After flag propagation, candidates may have new active conditional deps
        whose targets are missing from the mapping. This redos the full resolution
        for each affected mapping entry so the resolver can consider all constraints
        together."""

        self.propagate_use_flags()

        resolver = PhxResolver(self.discovered_ports)

        while True:
            re_resolved = False
            for namever, mapping in list(self.mapping.items()):
                has_missing = any(
                    req.name not in mapping
                    for cand in mapping.values()
                    if isinstance(cand, InstallableCandidate)
                    for req in cand.iter_dependencies()
                )
                if not has_missing:
                    continue

                # Re-resolve from the root requirement for this self.mapping entry
                self.resolve_for_namever(resolver, namever)
                re_resolved = True

            if not re_resolved:
                break

            # Newly resolved deps may carry propagated flags
            self.propagate_use_flags()

    def _get_state_dir(self) -> Path | None:
        if self._state_dir:
            return self._state_dir
        if not self.dry:
            return Path(os.environ["PREFIX_BUILD"]) / ".port_state"
        return None

    @staticmethod
    def _build_state(cand: InstallableCandidate) -> dict:
        return {"use_flags": sorted(cand.use_flags), "tests": cand.build_tests}

    def clean_stale_ports(self) -> None:
        """Compare current USE flag state with the saved state from the last
        build.  If any port's state changed, clean it and all transitive
        dependents so they are rebuilt from scratch."""
        state_dir = self._get_state_dir()
        if state_dir is None:
            return

        # Collect all unique InstallableCandidate objects across mappings
        all_cands: dict[str, InstallableCandidate] = {
            str(c): c
            for mapping in self.mapping.values()
            for c in mapping.values()
            if isinstance(c, InstallableCandidate)
        }

        # Find directly stale candidates (saved state differs from current)
        for nv, c in all_cands.items():
            state_file = state_dir / f"{nv}.json"
            if not state_file.exists():
                continue
            with open(state_file, encoding="utf-8") as f:
                saved = json.load(f)
            if saved != self._build_state(c):
                self.stale_ports.add(nv)

        if not self.stale_ports:
            return

        # Build reverse dependency graph: dep -> set of dependents
        rdeps: dict[str, set[str]] = {nv: set() for nv in all_cands}
        for mapping in self.mapping.values():
            for c in mapping.values():
                if not isinstance(c, InstallableCandidate):
                    continue
                for dep_c in c.iter_installable_dep_cands(mapping):
                    rdeps[str(dep_c)].add(str(c))

        # Propagate staleness transitively to dependents
        queue = list(self.stale_ports)
        while queue:
            nv = queue.pop()
            for dep_nv in rdeps.get(nv, []):
                if dep_nv not in self.stale_ports:
                    self.stale_ports.add(dep_nv)
                    queue.append(dep_nv)

        # Clean all stale candidates
        for nv in sorted(self.stale_ports):
            c = all_cands[nv]
            logger.info(f"Build state changed for {c}, cleaning")
            if not self.dry:
                env = os.environ.copy()
                env["PREFIX_PORT_INSTALL"] = c.install_path
                build_layer.clean_cand(c, env)
            # Remove saved state so it is re-saved after rebuild
            state_file = state_dir / f"{nv}.json"
            state_file.unlink(missing_ok=True)

    def save_build_state(self) -> None:
        """Persist build state for all installed ports."""
        state_dir = self._get_state_dir()
        if state_dir is None:
            return
        state_dir.mkdir(parents=True, exist_ok=True)
        for cand in self.ports_installed:
            if not isinstance(cand, InstallableCandidate):
                continue
            state_file = state_dir / f"{cand}.json"
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(self._build_state(cand), f)

    def resolve_for_namever(self, resolver: PhxResolver, namever: str):
        name, version = parse_namever(namever)
        ureq = BaseRequirement(name, [("==", version)])
        result = resolver.resolve([ureq])
        self.mapping[namever] = result.mapping

    def resolve(self, cands: list[InstallableCandidate]):
        self.add_os_candidates()
        resolver = PhxResolver(self.discovered_ports)
        for cand in cands:
            self.resolve_for_namever(resolver, str(cand))

    def read_ports_yaml(self) -> tuple[list[InstallableCandidate], set[str]]:
        ports_dict = self.get_ports_to_build(self.args.ports_yamls)

        if not ports_dict:
            logger.warning("No port requirements for target. Nothing to do")
            sys.exit(0)

        enable_tests = require_bool(ports_dict, "tests", True)

        if "ports" not in ports_dict or not ports_dict["ports"]:
            logger.error("no ports to install? (`ports:` not present in ports.yaml)")
            sys.exit(1)

        if not isinstance(ports_dict["ports"], list):
            logger.error("'ports' should be a list")
            sys.exit(1)

        cands: dict[str, InstallableCandidate] = dict()

        disabled_ports_list = ports_dict.get("disabled-ports", [])
        if not isinstance(disabled_ports_list, list) or any(
            not isinstance(i, str) for i in disabled_ports_list
        ):
            logger.error("'disabled-ports' should be a list of port names (strings)")
            sys.exit(1)
        disabled_ports = set(disabled_ports_list)

        for port in ports_dict["ports"]:
            if isinstance(port, str):
                port_name = port
            else:
                assert isinstance(port, dict)
                port_name = port["name"]

            if port_name not in self.discovered_ports:
                logger.error("unrecognized port:", port_name)
                sys.exit(1)

            if port_name in disabled_ports:
                logger.warning(f"Skipping {port_name} build due to disabled-ports")
                self.ports_skipped.append(port_name)
                continue

            port_cands = self.discovered_ports[port_name]

            if isinstance(port, dict) and "version" in port:
                # normalize
                ver = str(PhxVersion(port["version"]))

                if ver in port_cands:
                    cand = port_cands[ver]
                else:
                    logger.error(
                        f"Version '{ver}' for '{port_name}' not found. Possible choices: {list(port_cands.keys())}"
                    )
                    sys.exit(1)
            else:
                # get latest cand version
                cand = sorted(
                    port_cands.values(), key=lambda c: c.version, reverse=True
                )[0]

            if isinstance(port, dict):
                if not require_bool(port, "if", True):
                    cands.pop(str(cand), None)
                    continue

                cand.build_tests = require_bool(port, "tests", False) and enable_tests

                use_flags = port.get("use", None)
                if use_flags:
                    cand.set_use_flags(use_flags)

            if not isinstance(cand, InstallableCandidate):
                logger.error(f"{cand} is not installable!")
                sys.exit(1)

            cands[str(cand)] = cand

        return list(cands.values()), disabled_ports

    def print_install_summary(self) -> None:
        ports_str = ""
        for port in self.ports_installed:
            reasons = []
            if port.user_required:
                reasons.append("U")
            if port.needed_by:
                reasons += [f"D:{p}" for p in port.needed_by]

            flags_info = ""
            if port.use_flags:
                flag_details = []
                for flag in port.use_flags:
                    origins = port.use_flags_origins.get(flag, ["unknown"])
                    flag_details.append(f"+{flag} (by {', '.join(origins)})")
                flags_info = " [" + ", ".join(flag_details) + "]"

            ports_str += "\n * " + f"{port} ({', '.join(reasons)}){flags_info}"
        logger.info(
            "Install summary:",
            ports_str,
            "\nTrigger legend: 'U' - user requirement, 'D' - dependency",
        )
        if self.ports_skipped:
            logger.info(
                "Some user requirements were skipped due to disable-ports:",
                "".join(["\n * " + s for s in self.ports_skipped]),
            )

    def cmd_build(self) -> None:
        start = time.time()

        self.discover_ports()

        if self.build_all:
            cands, disabled_ports = list(
                [cand for ver in self.discovered_ports.values() for cand in
                    ver.values() if isinstance(cand, InstallableCandidate)]), set()
            logger.info("Building all ports")
        else:
            cands, disabled_ports = self.read_ports_yaml()

        if disabled_ports:
            for disabled_port_name in disabled_ports:
                self.discovered_ports.pop(disabled_port_name, None)
            logger.warning(
                "Some ports are ignored in resolution due to disable-ports:",
                "".join(["\n * " + s for s in disabled_ports]),
            )

        self.resolve(cands)
        self.resolve_propagated_deps()
        self.clean_stale_ports()

        # Erase prepare.log as it can grow pretty quickly across several rebuilds
        build_layer.erase_prepare_log(os.environ)

        for cand in cands:
            cand.user_required = True
            cand.install(
                self.mapping[str(cand)],
                roll_logs=self.roll_logs,
                dry=self.dry,
                ports_installed=self.ports_installed,
            )

        self.save_build_state()

        stop = time.time()

        logger.info(f"Done ({stop - start:.2f} s)")
        self.print_install_summary()

    def cmd_validate(self) -> None:
        start = time.time()
        self.discover_ports()
        stop = time.time()
        cand_str = json.dumps(
            self.discovered_ports,
            indent=2,
            default=lambda o: o.to_dict(self.args.ports_dir),
        )
        logger.info(
            f"[Total {stop - start:.2f} s] Validated {len(self.discovered_ports)} ports"
        )
        print(cand_str)

    def _build_argument_parser(self) -> ArgumentParser:
        parser = ArgumentParser(epilog="""
environment variables:
  RAW_LOG - if true, disables log rolling
  BUILD_ALL_PORTS - if true, build all discovered ports (note: optional dependencies are treated as required)
""", formatter_class=RawDescriptionHelpFormatter)

        parser.add_argument(
            "--dry",
            action="store_true",
            help="don't build ports, just mark them as installed",
        )
        parser.add_argument("-v", action="store_true")
        parser.add_argument("--quiet", action="store_true")

        subparsers = parser.add_subparsers(title="subcommands")

        build = subparsers.add_parser(
            "build", help="build ports based on ports.yaml config"
        )
        build.add_argument("ports_yamls", help="list of paths to ports.yamls")
        build.add_argument("ports_dir", help="path to ports directory")
        build.set_defaults(func=self.cmd_build)

        validate = subparsers.add_parser(
            "validate", help="validate all port definitions in ports directory"
        )
        validate.add_argument("ports_dir", help="path to ports directory")
        validate.set_defaults(func=self.cmd_validate)

        return parser

    def _parse_arguments(self, argv: Sequence[str]) -> Namespace:
        parser = self._build_argument_parser()
        if len(argv) == 1:
            parser.print_help()
        args = parser.parse_args(argv[1:])

        logger.set_level(LogLevel.INFO)

        if args.v:
            logger.set_level(LogLevel.VERBOSE)
        if args.quiet:
            logger.set_level(LogLevel.NONE)
        if sys.stdout.isatty() and not build_layer.env_to_bool("RAW_LOG"):
            self.roll_logs = True
        if build_layer.env_to_bool("BUILD_ALL_PORTS"):
            self.build_all = True
        if args.dry:
            logger.warning("Dry run")
            self.dry = True

        return args

    def run_cmd(self):
        if "func" in self.args:
            self.args.func()
