#
# Python build core
#
# CycloneDX SBOM common utils
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import hashlib
import json
import os
import sys
from functools import cache
from pathlib import Path
from typing import Iterable

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from license_expression import ExpressionError, get_spdx_licensing

from reuse.project import Project

from build_core.logger import logger


CDX_SPEC_VERSION = "1.6"
VENDOR = {"name": "Phoenix Systems", "url": ["https://phoenix-rtos.com"]}

spdx_licensing = get_spdx_licensing()


@cache
def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def cdx_hashes(path: Path) -> list[dict]:
    return [{"alg": "SHA-256", "content": sha256_file(path)}]


def cdx_file(path: Path, bom_ref: str) -> dict:
    return {
        "type": "file",
        "bom-ref": bom_ref,
        "name": path.name,
        "hashes": cdx_hashes(path),
    }


def cdx_licenses(expression: str, owner: str, license_text: str | None = None) -> list[dict]:
    """Converts human-declared SPDX license expression into CycloneDX
    licenses. A single LicenseRef is emitted with its text, if available"""
    info = spdx_licensing.validate(expression)
    unknown = [s for s in info.invalid_symbols if not s.startswith("LicenseRef-")]
    if unknown or (info.errors and not info.invalid_symbols):
        logger.error(f"{owner}: invalid SPDX license expression '{expression}':", unknown or info.errors)
        sys.exit(1)

    if info.invalid_symbols and license_text:
        if expression.strip() == info.invalid_symbols[0]:
            return [{
                "license": {
                    "name": info.invalid_symbols[0],
                    "text": {"content": license_text, "contentType": "text/plain"},
                    "acknowledgement": "concluded",
                }
            }]
        logger.warning(f"{owner}: license text of LicenseRef in compound expression '{expression}' is not embedded")

    return [{"expression": expression, "acknowledgement": "concluded"}]


def sanitize_license_symbols(symbols: list[str], directory_path: Path) -> Iterable[str]:
    """Workaround sanitizer for broken spdx_licensing.validate() (as of
    license_expression 30.4.4). Drops expressions with non-SPDX identifiers"""
    for symb in symbols:
        try:
            _ = spdx_licensing.parse(symb)
        except ExpressionError:
            continue
        unknown = [s for s in spdx_licensing.validate(symb).invalid_symbols if not s.startswith("LicenseRef-")]
        if unknown:
            logger.warning(f"{directory_path}: ignoring non-SPDX license identifier(s) {unknown} (use LicenseRef-...)")
            continue
        yield symb


@cache
def run_reuse_on_directory(directory_path: Path) -> tuple[list[str], str]:
    """Runs reuse tool on given path. Returns a pair: copyright notices and
    detected licenses SPDX expression (empty if none found)"""
    if not os.path.isdir(directory_path):
        raise FileNotFoundError(directory_path)

    project = Project(directory_path)
    unique_copyrights: set[str] = set()
    unique_licenses: set[str] = set()

    for filepath in project.all_files():
        try:
            for reuse_info in project.reuse_info_of(filepath):
                unique_copyrights.update(map(str, reuse_info.copyright_notices))
                unique_licenses.update(map(str, reuse_info.spdx_expressions))
        except Exception as e:
            logger.warning(f"Could not parse {filepath}: {e}")

    # As of reuse 6.2.0, the regex in reuse.extract.reuse_info_of_file() may
    # capture garbage at the end of the expressions, so we need to sanitize on
    # our own
    sanitized_sorted = sorted(sanitize_license_symbols(list(unique_licenses), directory_path))
    licenses_expr = " AND ".join([f"({lic})" for lic in sanitized_sorted])

    return sorted(unique_copyrights), licenses_expr


def write_valid_bom_or_exit(bom: dict, output_path: Path) -> None:
    serialized = json.dumps(bom, indent=2)

    error = JsonStrictValidator(SchemaVersion.from_version(CDX_SPEC_VERSION)).validate_str(serialized)
    if error:
        logger.error("Generated SBOM is invalid:", error.data)
        sys.exit(1)

    output_path.write_text(serialized + "\n", encoding="utf-8")
    logger.info(f"CycloneDX SBOM saved to {output_path.absolute()}")
