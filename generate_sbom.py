#!/usr/bin/env python3
#
# SPDX v2.2 SBOM aggregator
#
# Collects *.sbom.json fragment files emitted by the build system and
# combines them into a single SPDX 2.2 document.
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse
import json
import sys
from pathlib import Path
from enum import Enum

from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    Package,
    ExternalPackageRef,
    ExternalPackageRefCategory,
)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model.actor import Actor, ActorType

from build_core.logger import logger, LogLevel
from build_core import sbom_utils


DEFAULT_LICENSE = "BSD-3-Clause"


class GeneratedType(Enum):
    BINARY = "binary"
    STATIC_LIB = "static-lib"


def collect_sbom_jsons(build_dir: Path) -> list[dict]:
    fragments = []
    for path in sorted(build_dir.rglob("*.sbom.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            logger.warning(f"skipping {path}: {e}")
            continue
        fragments.append(data)
    return fragments


def build_spdx_document(
    fragments: list[dict],
    phoenix_version: str,
    build_dir: Path,
    ports_spdx_path: Path | None = None,
) -> Document:
    if ports_spdx_path:
        doc = parse_file(str(ports_spdx_path))
        logger.info(
            f"Loaded ports_spdx SPDX document: { ports_spdx_path}",
        )
    else:
        doc = sbom_utils.create_phoenix_spdx_document(phoenix_version)

    assert doc

    ports_spdx_ids: set[str] = {pkg.spdx_id for pkg in doc.packages}

    known: set[str] = {frag["name"] for frag in fragments}
    known.update(pkg.name for pkg in doc.packages)

    for frag in fragments:
        name = frag["name"]
        spdx_id = sbom_utils.name_to_pkg_spdx_id(name)
        if spdx_id in ports_spdx_ids:
            logger.error(f"Duplicate spdx ID: {spdx_id}")
            sys.exit(1)
        version = frag.get("version", "")
        if not version:
            logger.warning(
                f"Version not specified for {name}. Assuming {phoenix_version}"
            )
            version = phoenix_version
        makefile_path = Path(frag["makefile_path"])
        try:
            generated_type = GeneratedType(frag["type"])
        except (KeyError, ValueError):
            logger.error(f"Missing or invalid 'type' in SBOM fragment for {name}")
            sys.exit(1)
        cpe = frag.get("cpe", "")
        purl = frag.get("purl", "")
        concluded_license = frag.get("license", "")
        if not concluded_license:
            logger.warning(
                f"License not specified for {name}. Assuming {DEFAULT_LICENSE}"
            )
            # TODO: this is temporary only. We shouldn't automatically assume
            # any license. This should be human-assigned in all Makefiles
            concluded_license = DEFAULT_LICENSE

        ext_refs = []
        if cpe:
            ext_refs.append(
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.SECURITY,
                    reference_type="cpe23Type",
                    locator=cpe,
                )
            )
        if purl:
            ext_refs.append(
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator=purl,
                )
            )

        copyrights, licenses = sbom_utils.run_reuse_on_directory(makefile_path.parent)

        files = []
        relationships = []

        match generated_type:
            case GeneratedType.STATIC_LIB:
                libdir = build_dir / "lib"
                srcs = frag.get("srcs", "")
                headers = frag.get("headers", "")

                if srcs:
                    lib_file = sbom_utils.libpath_to_spdx_file(
                        libdir / f"{name}.a", concluded_license
                    )
                    files.append(lib_file)
                    relationships.append(
                        Relationship(
                            spdx_id, RelationshipType.GENERATES, lib_file.spdx_id
                        )
                    )
                elif headers:
                    # TODO: should we track the use of headers?
                    logger.warning(f"Header-only 'static-lib': {name}, ignored for now")
                else:
                    # should not happen
                    logger.error(f"{name} has empty srcs and headers")
                    sys.exit(1)

        pkg = Package(
            spdx_id=spdx_id,
            name=name,
            version=version,
            download_location=SpdxNoAssertion(),
            files_analyzed=bool(files),
            license_declared=spdx_licensing.parse(
                licenses if licenses else concluded_license
            ),
            license_concluded=spdx_licensing.parse(concluded_license),
            copyright_text=copyrights,
            external_references=ext_refs,
            supplier=Actor(ActorType.ORGANIZATION, sbom_utils.SPDX_PKG_VENDOR),
        )

        doc.packages.append(pkg)
        doc.relationships.append(
            Relationship(
                sbom_utils.SPDX_SYSTEM_PKG_ID, RelationshipType.CONTAINS, spdx_id
            )
        )

        deps = frag.get("deps", "").split() + frag.get("libs", "").split()
        for dep in deps:
            if dep in known:
                doc.relationships.append(
                    Relationship(
                        spdx_id,
                        RelationshipType.STATIC_LINK,
                        sbom_utils.name_to_lib_spdx_id(dep),
                    )
                )

        port_lib_deps = frag.get("ports_libs", "").split()
        for dep in port_lib_deps:
            doc.relationships.append(
                Relationship(
                    spdx_id,
                    RelationshipType.DEPENDS_ON,
                    sbom_utils.libpath_to_spdx_id(dep),
                )
            )

        doc.files.extend(files)
        doc.relationships.extend(relationships)

    return doc


def main() -> None:
    logger.set_level(LogLevel.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "build_dir",
        help="Root of the build tree (e.g. _build/ia32-generic-qemu)",
    )
    parser.add_argument("phoenix_version", help="Phoenix version tag")
    parser.add_argument("output", help="Output SPDX JSON file")
    parser.add_argument(
        "-p",
        "--ports-spdx",
        help="Ports SPDX file to extend (must contain the firmware package)",
    )
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    if not build_dir.is_dir():
        sys.exit(f"error: {build_dir} is not a directory")

    json_frags = collect_sbom_jsons(build_dir)
    if not json_frags:
        sys.exit(f"error: no *.sbom.json files found under {build_dir}")

    logger.info(f"Collected {len(json_frags)} SBOM fragments")

    ports_spdx_path = Path(args.ports_spdx) if args.ports_spdx else None
    if ports_spdx_path and not ports_spdx_path.is_file():
        print(f"{ports_spdx_path} does not exist, creating new document")
        ports_spdx_path = None

    doc = build_spdx_document(
        json_frags, args.phoenix_version, build_dir, ports_spdx_path
    )

    sbom_utils.write_valid_document_to_file_or_exit(doc, Path(args.output))


if __name__ == "__main__":
    main()
