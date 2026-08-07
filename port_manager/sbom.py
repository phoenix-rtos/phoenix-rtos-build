#
# Port management
#
# SPDX v2.2 SBOM generation
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from pathlib import Path

import os
import sys

from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.extracted_licensing_info import ExtractedLicensingInfo
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.common.spdx_licensing import spdx_licensing  # type: ignore[import-untyped]
from spdx_tools.spdx.model.package import ExternalPackageRef, ExternalPackageRefCategory

from .candidates import Candidate, InstallableCandidate

from build_core.logger import logger
from build_core import sbom_utils


def cand_to_spdx_id(cand: Candidate):
    name = cand.name.replace("_", "-")  # spdx_id must not contain `_`
    return f"SPDXRef-Package-{name}"


def port_to_pkg_ref(port: InstallableCandidate) -> ExternalPackageRef:
    if not port.cpe23:
        locator = f"pkg:generic/{port.name}@{str(port.version)}"
        logger.warning(f"no cpe23 defined, using fallback PURL: {locator}")
        return ExternalPackageRef(
            category=ExternalPackageRefCategory.PACKAGE_MANAGER,
            reference_type="purl",
            locator=locator,
        )
    else:
        return ExternalPackageRef(
            category=ExternalPackageRefCategory.SECURITY,
            reference_type="cpe23Type",
            locator=port.cpe23,
        )


class PortsSbom:
    def __init__(self, phoenix_version: str):
        self.custom_license_ids = set()
        self.phoenix_version = phoenix_version
        self.doc = sbom_utils.create_phoenix_spdx_document(self.phoenix_version)

    def _emit_license_if_custom(self, port):
        """Checks if port's declared license is a LicenseRef. If so, tries to
        extract licensing info from the port's license_path"""
        validation_info = spdx_licensing.validate(port.license)
        if validation_info.invalid_symbols:
            license_id = validation_info.invalid_symbols[0]
            if (
                len(validation_info.invalid_symbols) == 1
                and port.license_path
                and license_id.startswith("LicenseRef-")
            ):
                logger.warning(
                    f"{port} has a custom license: {license_id}. Extracting from {port.license_path}"
                )
                if license_id not in self.custom_license_ids:
                    with open(port.license_path, "r", encoding="utf-8") as file:
                        license_text = file.read()
                    custom_license = ExtractedLicensingInfo(
                        license_id=license_id,
                        extracted_text=license_text,
                    )
                    self.doc.extracted_licensing_info.append(custom_license)
                    self.custom_license_ids.add(license_id)
            else:
                logger.error(
                    "invalid symbols found in 'license' or no license_path to fall back to:",
                    validation_info.invalid_symbols
                )
                sys.exit(1)

    def generate(
        self,
        ports_installed: list[InstallableCandidate],
        output_path: Path,
    ):
        for port in ports_installed:
            logger.info(f"generating SBOM for {port}")

            port_id = cand_to_spdx_id(port)
            port_name = port.name
            port_version = str(port.version)

            pkg_ref = port_to_pkg_ref(port)

            copyrights, licenses = sbom_utils.run_reuse_on_directory(
                Path(os.environ["PREFIX_BUILD"]) / "port-sources" / str(port)
            )

            port_location = port.origin_source

            self._emit_license_if_custom(port)

            pkg = Package(
                spdx_id=port_id,
                name=port_name,
                version=port_version,
                download_location=port_location,
                files_analyzed=bool(port.built_libs),
                checksums=[Checksum(ChecksumAlgorithm.SHA256, port.sha256)],
                license_declared=spdx_licensing.parse(
                    licenses if licenses else port.license
                ),
                # this is the final human-declared license expression from port.def.sh
                license_concluded=spdx_licensing.parse(port.license),
                copyright_text=copyrights,
                external_references=[pkg_ref],
                # TODO: pass explicit vendor in port defs?...
                supplier=Actor(ActorType.ORGANIZATION, port_name),
            )

            self.doc.packages.append(pkg)

            self.doc.relationships.append(
                Relationship(
                    sbom_utils.SPDX_SYSTEM_PKG_ID, RelationshipType.CONTAINS, port_id
                )
            )

            for rdep in port.needed_by:
                self.doc.relationships.append(
                    Relationship(
                        cand_to_spdx_id(rdep),
                        RelationshipType.DEPENDS_ON,
                        port_id,
                    )
                )

            for lib_path in port.built_libs:
                static_lib_file = sbom_utils.libpath_to_spdx_file(
                    lib_path, port.license
                )
                self.doc.files.append(static_lib_file)
                self.doc.relationships.append(
                    Relationship(
                        port_id, RelationshipType.GENERATES, static_lib_file.spdx_id
                    )
                )

        sbom_utils.write_valid_document_to_file_or_exit(self.doc, output_path)
