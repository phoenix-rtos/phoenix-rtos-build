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
from typing import TypeVar
from collections.abc import Callable
from collections.abc import Sequence, Generator

import sys
import time
import json

from pathlib import Path

from argparse import Namespace, ArgumentParser

from .version import PhxVersion, PhxVersionGrammar
from .logger import logger, LogLevel
from .requirements import (
    BaseRequirement,
    OptionalRequirement,
    ConflictRequirement,
    Constraint,
)
from .candidates import Candidate, OsCandidate, InstallableCandidate
from .resolver import PhxResolver, CandidatesDict
from . import build_layer

T = TypeVar("T")


def parse_requirements(s: str, f: Callable[[str, list[Constraint]], T]) -> list[T]:
    requirements_objects = []
    if s:
        requirements_tuples: dict[str, list[Constraint]] = dict()

        res = PhxVersionGrammar.parse_string(s)
        for rname, rel, ver in res:
            if rname not in requirements_tuples:
                requirements_tuples[rname] = []
            requirements_tuples[rname].append((rel, ver))

        for rname, constraints in requirements_tuples.items():
            logger.debug(constraints)
            requirements_objects.append(f(rname, constraints))

    return requirements_objects


def parse_namever(namever: str) -> Constraint:
    elems = namever.split("-")
    if len(elems) != 2:
        raise ValueError(f"bad name-ver - expected NAME-VERSION, got '{namever}'")
    return (elems[0], PhxVersion(elems[1]))


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
    ) -> None:
        self.discovered_ports: CandidatesDict = dict()
        self.os_candidates_added = False

        self.mapping: CandidatesDict = dict()
        self.roll_logs = False
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
            phoenix_ver = build_layer.ensure_getenv("PHOENIX_VER").split("-", 1)[0]

            self.add_candidate(OsCandidate("phoenix", PhxVersion(phoenix_ver)))
            self.add_candidate(OsCandidate("host", PhxVersion("0")))
            self.os_candidates_added = True

    def discover_ports(self):
        for port, def_path in self.find_ports(self.args.ports_dir):
            name, version = parse_namever(port["namever"])

            req = parse_requirements(port["requires"], BaseRequirement)
            req += parse_requirements(port["optional"], OptionalRequirement)
            req += parse_requirements(port["supports"], BaseRequirement)

            conflicts = parse_requirements(
                port["conflicts"],
                lambda r, c: ConflictRequirement(name, r, c),
            )

            if not def_path:
                raise ValueError("Empty definition path")

            available_flags = port["iuse"].split()

            self.add_candidate(
                InstallableCandidate(
                    name,
                    version,
                    req,
                    conflicts,
                    str(def_path),
                    available_flags,
                    port["desc"],
                )
            )

    def resolve(self, cands: list[InstallableCandidate]):
        user_requirements = dict()

        for cand in cands:
            user_requirements[str(cand)] = BaseRequirement(
                cand.name, [("==", cand.version)]
            )

        self.add_os_candidates()

        resolver = PhxResolver(self.discovered_ports)

        for namever, ureq in user_requirements.items():
            result = resolver.resolve([ureq])
            self.mapping[namever] = result.mapping

    def read_ports_yaml(self) -> tuple[list[InstallableCandidate], list[str]]:
        ports_dict = self.get_ports_to_build(self.args.ports_yamls)

        if not ports_dict:
            logger.warning("No port requirements for target. Nothing to do")
            sys.exit(0)

        enable_tests = ports_dict.get("tests", True)

        if "ports" not in ports_dict or not ports_dict["ports"]:
            logger.error("no ports to install? (`ports:` not present in ports.yaml)")
            sys.exit(1)

        cands: dict[str, InstallableCandidate] = dict()

        disabled_ports = ports_dict.get("disabled-ports", [])
        if not isinstance(disabled_ports, list) or any(not isinstance(i, str) for i in disabled_ports):
            logger.error("'disabled-ports' should be a list of port names (strings)")
            sys.exit(1)
        disabled_ports = set(disabled_ports)

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
                if not port.get("if", True):
                    cands.pop(str(cand), None)
                    continue

                cand.build_tests = port.get("tests", False) and enable_tests

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
            ports_str += "\n * " + f"{port} ({', '.join(reasons)})"
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

        cands, disabled_ports = self.read_ports_yaml()

        if disabled_ports:
            for disabled_port_name in disabled_ports:
                self.discovered_ports.pop(disabled_port_name, None)
            logger.warning(
                "Some ports are ignored in resolution due to disable-ports:",
                "".join(["\n * " + s for s in disabled_ports]),
            )

        self.resolve(cands)

        for cand in cands:
            cand.user_required = True
            cand.install(
                self.mapping[str(cand)],
                roll_logs=self.roll_logs,
                dry=self.dry,
                ports_installed=self.ports_installed,
            )

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
            f"[Total {stop - start:.2f} s] Validated {len(self.discovered_ports)} ports",
        )
        print(cand_str)

    def _build_argument_parser(self) -> ArgumentParser:
        parser = ArgumentParser()

        parser.add_argument(
            "--dry",
            action="store_true",
            help="don't build ports, just mark them as installed",
        )
        parser.add_argument("-v", action="store_true")
        parser.add_argument(
            "-r",
            action="store_true",
            default=False,
            help="roll build logs (i.e. for interactive environment)",
        )
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
        if args.r:
            self.roll_logs = True
        if args.dry:
            logger.warning("Dry run")
            self.dry = True

        return args

    def run_cmd(self):
        if "func" in self.args:
            self.args.func()
