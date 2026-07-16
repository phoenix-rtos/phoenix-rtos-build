#!/usr/bin/env python3
#
# CycloneDX SBOM generator
#
# Collects *.sbom.json fragments emitted by the build system (Makefile
# components and ports), determines which components end up in the firmware
# image and emits a CycloneDX SBOM describing the image.
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse
import json
import os
import sys
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from build_core.logger import logger, LogLevel
from build_core import sbom_utils


DEFAULT_LICENSE = "BSD-3-Clause"
LIBC_NAME = "libphoenix"
FIRMWARE_REF = "firmware"

CDX_TYPES = {
    "binary": "application",
    "static-lib": "library",
    "kernel": "operating-system",
    "bootloader": "firmware",
}

# fragment types that are linked statically into their dependents
LINKABLE_TYPES = ("static-lib", "port")


@dataclass
class Component:
    frag: dict
    name: str
    kind: str
    version: str
    artifacts: list[Path]
    dep_names: set[str]
    dep_lib_paths: set[Path]
    occurrences: set[str] = field(default_factory=set)

    @property
    def bom_ref(self) -> str:
        return self.name

    @property
    def cdx_type(self) -> str:
        if self.kind == "port":
            return "library" if all(p.suffix == ".a" for p in self.artifacts) else "application"
        return CDX_TYPES[self.kind]


def collect_fragments(build_dir: Path) -> list[dict]:
    fragments = []
    for path in sorted(build_dir.rglob("*.sbom.json")):
        # don't pick up files that may come with upstream port sources
        if "port-sources" in path.relative_to(build_dir).parts:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            logger.warning(f"skipping {path}: {e}")
            continue
        if not isinstance(data, dict) or "name" not in data or "type" not in data:
            logger.warning(f"skipping {path}: not an SBOM fragment")
            continue
        data["fragment_path"] = str(path)
        fragments.append(data)
    return fragments


def fragment_to_component(frag: dict, phoenix_version: str) -> Component:
    kind = frag["type"]
    if kind not in CDX_TYPES and kind != "port":
        logger.error(f"invalid type '{kind}' in SBOM fragment {frag['fragment_path']}")
        sys.exit(1)

    artifacts = frag.get("artifacts", [])
    if isinstance(artifacts, str):
        artifacts = artifacts.split()

    if kind == "port":
        dep_names = set(frag.get("deps", []))
        dep_lib_paths = set()
    else:
        dep_names = set(frag.get("deps", "").split())
        if kind == "binary":
            dep_names.add(LIBC_NAME)
        dep_lib_paths = {Path(p) for p in frag.get("ports_libs", "").split()}

    # the same file may be installed in several places (e.g. prog.stripped and rootfs)
    unique_artifacts: dict[str, Path] = {}
    for artifact in map(Path, artifacts):
        if artifact.is_file():
            unique_artifacts.setdefault(sbom_utils.sha256_file(artifact), artifact)

    return Component(
        frag=frag,
        name=frag["name"],
        kind=kind,
        version=frag.get("version") or phoenix_version,
        artifacts=list(unique_artifacts.values()),
        dep_names=dep_names,
        dep_lib_paths=dep_lib_paths,
    )


def iter_image_files(rootfs: Path | None, rootfs_snapshot: Path | None, manifest: Path | None):
    """Yields (location, path, sha256) of files put into the image. The hash is
    the one recorded when the image was built (None if not recorded)"""
    if rootfs and rootfs_snapshot:
        # sha256sum output taken in rootfs dir: "<hash>  ./<path>"
        for line in rootfs_snapshot.read_text(encoding="utf-8").splitlines():
            sha256, _, relpath = line.partition("  ")
            location = "/" + relpath.removeprefix("./")
            yield location, rootfs / relpath, sha256
    elif rootfs:
        for path in sorted(rootfs.rglob("*")):
            if path.is_file() and not path.is_symlink():
                yield "/" + str(path.relative_to(rootfs)), path, None

    if manifest:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            image = Path(record["image"]).name
            for content in record["contents"]:
                path = Path(content["path"])
                yield f"{image}:{path.name}", path, content["sha256"]


def is_elf(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"\x7fELF"


class SbomGenerator:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.components: dict[str, Component] = {}
        self.by_hash: dict[str, Component] = {}
        self.by_path: dict[Path, Component] = {}
        self.unattributed_libs: set[Path] = set()

    def load(self, fragments: list[dict]) -> None:
        for frag in fragments:
            comp = fragment_to_component(frag, self.args.phoenix_version)
            if comp.name in self.components:
                other = self.components[comp.name].frag["fragment_path"]
                logger.error(
                    f"Duplicate component '{comp.name}': {frag['fragment_path']} and {other}",
                    "(stale fragment? try a clean build)",
                )
                sys.exit(1)
            self.components[comp.name] = comp
            for artifact in comp.artifacts:
                self.by_hash[sbom_utils.sha256_file(artifact)] = comp
                self.by_path[artifact.resolve()] = comp

    def find_image_roots(self) -> set[str]:
        roots: set[str] = set()
        unmatched: list[str] = []
        outdated: list[str] = []

        image_contents = iter_image_files(self.args.rootfs, self.args.rootfs_snapshot, self.args.manifest)
        for location, path, recorded in image_contents:
            current = sbom_utils.sha256_file(path) if path.is_file() else None
            if recorded and current and recorded != current:
                outdated.append(location)
                continue
            comp = self.by_hash.get(recorded or current or "")
            if comp is None and ":" in location:
                # files derived from an artifact (e.g. kernel .bin from .elf)
                comp = next(
                    (c for a, c in self.by_path.items() if a.parent == path.resolve().parent and a.stem == path.stem),
                    None,
                )
            if comp is not None:
                comp.occurrences.add(location)
                roots.add(comp.name)
            elif current and is_elf(path):
                unmatched.append(location)

        if unmatched:
            logger.warning(
                "Executables in the image not matching any SBOM component:",
                "".join(f"\n * {u}" for u in unmatched),
            )

        if outdated:
            logger.error(
                "Files changed since the image was built, rebuild the image first:",
                "".join(f"\n * {o}" for o in outdated),
            )
            sys.exit(1)

        return roots

    def resolve_deps(self, comp: Component) -> set[str]:
        deps = set()
        for name in comp.dep_names:
            dep = self.components.get(name)
            if dep is not None and dep is not comp and (comp.kind == "port" or dep.kind in LINKABLE_TYPES):
                deps.add(name)
        for lib_path in comp.dep_lib_paths:
            dep = self.by_path.get(lib_path.resolve())
            if dep is not None:
                deps.add(dep.name)
            else:
                self.unattributed_libs.add(lib_path)
        return deps

    def closure(self, roots: set[str]) -> set[str]:
        included = set(roots)
        queue = deque(roots)
        while queue:
            for dep in self.resolve_deps(self.components[queue.popleft()]):
                if dep not in included:
                    included.add(dep)
                    queue.append(dep)
        return included

    def load_vendored(self, comp: Component) -> tuple[list[dict], list[dict]]:
        """Loads components of all SBOMs vendored by comp (LOCAL_SBOM may list several)"""
        components: list[dict] = []
        dependencies: list[dict] = []
        for path in comp.frag["extra_sbom"].split():
            sub_components, sub_dependencies = self.load_vendored_file(comp, Path(path))
            components += sub_components
            dependencies += sub_dependencies
        return components, dependencies

    def load_vendored_file(self, comp: Component, path: Path) -> tuple[list[dict], list[dict]]:
        """Loads components of a single CycloneDX SBOM vendored by comp"""
        if not path.is_file():
            logger.error(f"{comp.name}: LOCAL_SBOM {path} does not exist")
            sys.exit(1)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            logger.error(f"{comp.name}: LOCAL_SBOM {path} is not valid JSON: {e}")
            sys.exit(1)

        if data.get("bomFormat") != "CycloneDX":
            logger.error(f"{comp.name}: LOCAL_SBOM {path} is not a CycloneDX SBOM")
            sys.exit(1)

        refs: dict[str, str] = {}

        def remap(components: list[dict]) -> None:
            for sub in components:
                old_ref = sub.get("bom-ref", sub["name"])
                refs[old_ref] = f"{comp.bom_ref}/{old_ref}"
                sub["bom-ref"] = refs[old_ref]
                if "supplier" not in sub:
                    logger.warning(f"{comp.name}: vendored component '{sub['name']}' has no supplier")
                remap(sub.get("components", []))

        components = data.get("components", [])
        remap(components)

        dependencies = []
        for dep in data.get("dependencies", []):
            if dep["ref"] in refs:
                dependencies.append({
                    "ref": refs[dep["ref"]],
                    "dependsOn": [refs[d] for d in dep.get("dependsOn", []) if d in refs],
                })

        return components, dependencies

    def component_to_cdx(self, comp: Component, license_fallbacks: list[str]) -> tuple[dict, list[dict]]:
        frag = comp.frag
        cdx: dict = {
            "type": comp.cdx_type,
            "bom-ref": comp.bom_ref,
            "name": comp.name,
            "version": comp.version,
        }

        if comp.kind == "port":
            # TODO: pass explicit vendor in port defs?...
            cdx["supplier"] = {"name": comp.name}
            reuse_dir = Path(frag["source_dir"])
            definition_dir = frag.get("definition_dir", "")
        else:
            cdx["supplier"] = sbom_utils.VENDOR
            reuse_dir = Path(frag["makefile_path"]).parent
            definition_dir = str(reuse_dir)

        license_expr = frag.get("license", "")
        if not license_expr:
            # TODO: this is temporary only. We shouldn't automatically assume
            # any license. This should be human-assigned in all Makefiles
            license_fallbacks.append(comp.name)
            license_expr = DEFAULT_LICENSE

        license_text = None
        if frag.get("license_path") and os.path.isfile(frag["license_path"]):
            license_text = Path(frag["license_path"]).read_text(encoding="utf-8", errors="replace")
        cdx["licenses"] = sbom_utils.cdx_licenses(license_expr, comp.name, license_text)

        copyrights: list[str] = []
        detected_licenses = ""
        if reuse_dir.is_dir():
            copyrights, detected_licenses = sbom_utils.run_reuse_on_directory(reuse_dir)
        if copyrights:
            cdx["copyright"] = "\n".join(copyrights)

        cpe = frag.get("cpe", "")
        purl = frag.get("purl", "")
        if cpe:
            cdx["cpe"] = cpe
        if purl:
            cdx["purl"] = purl
        if not cpe and not purl:
            namespace = "" if comp.kind == "port" else "phoenix-rtos/"
            cdx["purl"] = f"pkg:generic/{namespace}{comp.name}@{comp.version}"
            if comp.kind == "port":
                logger.warning(f"{comp.name}: no cpe23 defined, using fallback PURL: {cdx['purl']}")

        if len(comp.artifacts) == 1:
            cdx["hashes"] = sbom_utils.cdx_hashes(comp.artifacts[0])

        if comp.kind == "port":
            cdx["externalReferences"] = [{
                "type": "distribution" if frag["source_kind"] == "tarball" else "vcs",
                "url": frag["download_location"],
                "hashes": [{"alg": "SHA-256", "content": frag["source_sha256"]}],
            }]

        evidence: dict = {}
        if detected_licenses:
            evidence["licenses"] = [{"expression": detected_licenses, "acknowledgement": "declared"}]
        if copyrights:
            evidence["copyright"] = [{"text": c} for c in copyrights]
        if comp.occurrences:
            evidence["occurrences"] = [{"location": loc} for loc in sorted(comp.occurrences)]
        if evidence:
            cdx["evidence"] = evidence

        properties = self.source_properties(definition_dir)
        if properties:
            cdx["properties"] = properties

        subcomponents = []
        if len(comp.artifacts) > 1:
            subcomponents += [sbom_utils.cdx_file(a, f"{comp.bom_ref}#{a.name}") for a in comp.artifacts]

        dependencies: list[dict] = []
        if frag.get("extra_sbom"):
            vendored, dependencies = self.load_vendored(comp)
            subcomponents += vendored

        if subcomponents:
            cdx["components"] = subcomponents

        return cdx, dependencies

    def source_properties(self, definition_dir: str) -> list[dict]:
        """phoenix:source - directory the component is defined in (its Makefile or port definition),
        phoenix:repository - git repository containing it ("." - the project repository itself), both
        relative to the project root. Lets consumers tell the project's own components from the
        ones of the repositories it's built from"""
        if not definition_dir:
            return []
        project = self.args.project_dir.resolve()
        path = Path(definition_dir).resolve()
        if not path.is_relative_to(project):
            return []
        properties = [{"name": "phoenix:source", "value": str(path.relative_to(project))}]
        repo = next((d for d in (path, *path.parents) if d.is_relative_to(project) and (d / ".git").exists()), None)
        if repo is not None:
            properties.append({"name": "phoenix:repository", "value": str(repo.relative_to(project))})
        return properties

    def image_files(self) -> list[Path]:
        boot_dir: Path = self.args.boot_dir
        if self.args.image_files:
            files = [boot_dir / f for f in self.args.image_files.split()]
            missing = [str(f) for f in files if not f.is_file()]
            if missing:
                logger.error("Image files not found:", missing)
                sys.exit(1)
            return files

        exclude = set(self.args.exclude)
        return sorted(
            p for p in boot_dir.iterdir()
            if p.is_file() and p.name not in exclude and p.resolve() != self.args.output.resolve()
            and not p.name.endswith(".cdx.json")
        )

    def firmware_component(self, created: datetime, files: list[Path]) -> dict:
        primary = None
        if self.args.primary_image:
            primary = self.args.boot_dir / self.args.primary_image
            if not primary.is_file():
                logger.error(f"Primary image {primary} not found")
                sys.exit(1)
        else:
            disks = [f for f in files if f.suffix == ".disk"]
            if len(disks) == 1:
                primary = disks[0]
            else:
                logger.warning("Can't determine the primary image (set SBOM_PRIMARY_IMAGE), firmware hash not emitted")

        firmware: dict = {
            "type": "firmware",
            "bom-ref": FIRMWARE_REF,
            "name": f"phoenix-rtos-{self.args.target}",
            "version": self.args.phoenix_version,
            "supplier": sbom_utils.VENDOR,
            "licenses": [{"expression": DEFAULT_LICENSE, "acknowledgement": "concluded"}],
            "copyright": f"Copyright {created.year} Phoenix Systems",
        }
        if primary:
            firmware["hashes"] = sbom_utils.cdx_hashes(primary)
        if files:
            firmware["components"] = [sbom_utils.cdx_file(f, f"{FIRMWARE_REF}#{f.name}") for f in files]
        else:
            logger.warning(f"No image files found in {self.args.boot_dir}")

        return firmware

    def generate(self) -> dict:
        created = datetime.now(timezone.utc)
        image_files = self.image_files()

        if self.args.scope == "image":
            roots = self.find_image_roots()
            included = self.closure(roots)
            excluded = sorted(set(self.components) - included)
            if excluded:
                logger.info("Components built but not in the image:", " ".join(excluded))
        else:
            self.find_image_roots()
            included = set(self.components)
            linked = set().union(*(self.resolve_deps(self.components[n]) for n in included))
            roots = included - linked

        components = []
        dependencies = [{"ref": FIRMWARE_REF, "dependsOn": sorted(roots)}]
        license_fallbacks: list[str] = []
        for name in sorted(included):
            comp = self.components[name]
            cdx, vendored_deps = self.component_to_cdx(comp, license_fallbacks)
            components.append(cdx)
            dependencies.append({"ref": comp.bom_ref, "dependsOn": sorted(self.resolve_deps(comp))})
            dependencies += vendored_deps

        if self.unattributed_libs:
            logger.warning(
                "Linked port libraries not attributed to any port (missing from SBOM):",
                "".join(f"\n * {p}" for p in sorted(self.unattributed_libs)),
            )

        if license_fallbacks:
            logger.warning(f"License not specified, assuming {DEFAULT_LICENSE} for:", " ".join(license_fallbacks))

        roots_desc = "found directly in the image" if self.args.scope == "image" else "top-level"
        logger.info(f"{len(components)} components in SBOM ({len(roots)} {roots_desc})")

        return {
            "bomFormat": "CycloneDX",
            "specVersion": sbom_utils.CDX_SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lifecycles": [{"phase": "build"}],
                "tools": {
                    "components": [{
                        "type": "application",
                        "group": "phoenix-rtos-build",
                        "name": Path(__file__).name,
                        "version": self.args.phoenix_version,
                    }],
                },
                "authors": [{"name": sbom_utils.VENDOR["name"]}],
                "supplier": sbom_utils.VENDOR,
                "component": self.firmware_component(created, image_files),
                "properties": [
                    {"name": "phoenix:target", "value": self.args.target},
                    {"name": "phoenix:sbom-scope", "value": self.args.scope},
                ] + [
                    {"name": f"phoenix:{key}", "value": value}
                    for key, _, value in (p.partition("=") for p in self.args.property)
                ],
            },
            "components": components,
            "dependencies": dependencies,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM of the firmware image")
    parser.add_argument("--build-dir", required=True, type=Path, help="root of the build tree")
    parser.add_argument("--boot-dir", required=True, type=Path, help="directory with the image files")
    parser.add_argument("--target", required=True, help="TARGET identification string")
    parser.add_argument("--phoenix-version", required=True, help="Phoenix-RTOS version")
    parser.add_argument("-o", "--output", required=True, type=Path, help="output CycloneDX JSON file")
    parser.add_argument(
        "--project-dir", type=Path, default=Path(os.environ.get("PREFIX_PROJECT") or "."),
        help="project root, component sources are recorded relative to it (env: PREFIX_PROJECT, default: current dir)",
    )
    parser.add_argument("--manifest", type=Path, help="image manifest written by image_builder.py")
    parser.add_argument("--rootfs", type=Path, help="rootfs dir put into the image")
    parser.add_argument("--rootfs-snapshot", type=Path, help="sha256sum of rootfs files taken when the image was built")
    parser.add_argument(
        "--scope", choices=("image", "build"), default=os.environ.get("SBOM_SCOPE") or "image",
        help="'image' - components found in the image and their dependencies, 'build' - all built (env: SBOM_SCOPE)",
    )
    parser.add_argument(
        "--image-files", default=os.environ.get("SBOM_IMAGE_FILES"),
        help="space-separated image files in boot dir (env: SBOM_IMAGE_FILES, default: all files except --exclude)",
    )
    parser.add_argument(
        "--primary-image", default=os.environ.get("SBOM_PRIMARY_IMAGE"),
        help="image file in boot dir identifying the firmware (env: SBOM_PRIMARY_IMAGE, default: the only *.disk file)",
    )
    parser.add_argument("--exclude", nargs="*", default=[], help="non-image file names in boot dir")
    parser.add_argument(
        "--property", action="append", default=[], metavar="KEY=VALUE",
        help="property added to SBOM metadata as phoenix:KEY (e.g. product, family, subfamily, project, mmu)",
    )
    args = parser.parse_args()

    if not args.build_dir.is_dir():
        sys.exit(f"error: {args.build_dir} is not a directory")
    if not args.boot_dir.is_dir():
        sys.exit(f"error: {args.boot_dir} is not a directory")
    if args.manifest and not args.manifest.is_file():
        logger.warning(f"Image manifest {args.manifest} not found (image not built?)")
        args.manifest = None
    if args.rootfs and args.rootfs_snapshot and not args.rootfs_snapshot.is_file():
        logger.warning(f"rootfs snapshot {args.rootfs_snapshot} not found (image not built?), using current rootfs")
        args.rootfs_snapshot = None
    if args.rootfs and not args.rootfs.is_dir():
        logger.warning(f"rootfs {args.rootfs} not found")
        args.rootfs = None
    if args.scope == "image" and not args.manifest and not args.rootfs:
        logger.error("Neither image manifest nor rootfs available, can't determine image contents")
        sys.exit(1)

    return args


def main() -> None:
    logger.set_level(LogLevel.INFO)
    args = parse_args()

    fragments = collect_fragments(args.build_dir)
    if not fragments:
        sys.exit(f"error: no *.sbom.json files found under {args.build_dir}")
    logger.info(f"Collected {len(fragments)} SBOM fragments")

    generator = SbomGenerator(args)
    generator.load(fragments)
    bom = generator.generate()

    sbom_utils.write_valid_bom_or_exit(bom, args.output)


if __name__ == "__main__":
    main()
