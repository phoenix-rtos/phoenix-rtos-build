#
# Port management
#
# SBOM metadata fragments of installed ports
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import json
import os
import shutil

from pathlib import Path

from .candidates import InstallableCandidate

from build_core.logger import logger


def get_fragments_dir() -> Path:
    return Path(os.environ["PREFIX_BUILD"]) / "ports-sbom"


def port_to_fragment(port: InstallableCandidate, deps: list[str], artifacts: list[str]) -> dict:
    return {
        "name": port.name,
        "version": str(port.version),
        "type": "port",
        "license": port.license,
        "license_path": port.license_path or "",
        "cpe": port.cpe23,
        "download_location": port.origin_source,
        "source_kind": "tarball" if "tarball" in port.sources else "git",
        "source_sha256": port.sha256,
        "source_dir": str(Path(os.environ["PREFIX_BUILD"]) / "port-sources" / str(port)),
        "definition_dir": str(Path(port.definition_path).resolve().parent),
        "deps": deps,
        "artifacts": artifacts,
    }


def load_previous_artifacts(frag_dir: Path) -> dict[str, list[str]]:
    """Returns artifacts of ports from the previous run, indexed by port name-version"""
    artifacts = {}
    for path in frag_dir.glob("*.sbom.json"):
        try:
            frag = json.loads(path.read_text(encoding="utf-8"))
            artifacts[f"{frag['name']}-{frag['version']}"] = frag["artifacts"]
        except (OSError, ValueError, KeyError) as e:
            logger.warning(f"ignoring previous SBOM fragment {path}: {e}")
    return artifacts


def write_fragments(ports_installed: list[InstallableCandidate], stale_ports: set[str]) -> None:
    """Writes SBOM metadata fragments of installed ports to be collected by
    generate_sbom.py. Fragments of ports not installed in this run are removed."""
    frag_dir = get_fragments_dir()
    previous_artifacts = load_previous_artifacts(frag_dir)
    shutil.rmtree(frag_dir, ignore_errors=True)
    frag_dir.mkdir(parents=True)

    deps: dict[str, set[str]] = {port.name: set() for port in ports_installed}
    for port in ports_installed:
        for rdep in port.needed_by:
            deps.setdefault(rdep.name, set()).add(port.name)

    for port in ports_installed:
        artifacts = {str(p.absolute()) for p in port.built_libs + port.built_progs}
        # incremental port build may skip installing unchanged files - keep the ones
        # installed previously, unless the port was cleaned
        if str(port) not in stale_ports:
            artifacts.update(p for p in previous_artifacts.get(str(port), []) if os.path.isfile(p))

        frag = port_to_fragment(port, sorted(deps[port.name]), sorted(artifacts))
        with open(frag_dir / f"{port.name}.sbom.json", "w", encoding="utf-8") as f:
            json.dump(frag, f, indent=2)

    logger.info(f"SBOM fragments of {len(ports_installed)} ports written to {frag_dir}")
