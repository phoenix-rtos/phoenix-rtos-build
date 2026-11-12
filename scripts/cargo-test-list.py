#!/usr/bin/env python3
#
# Lists the test executables of a crate for rust-cargo.mk
#
# usage: cargo-test-list.py <messages.json> <component name>
#
# Reads `cargo test --no-run --message-format=json` output and prints a
# "<test name> <executable>" line per test executable: test-<component> for the
# target named after the component (its binary or library), test-<component>-<target>
# for the others. Cargo's own names carry a hash, too unstable for test configurations.
#
# Copyright 2026 Phoenix Systems
#
# SPDX-License-Identifier: BSD-3-Clause
#

import json
import sys


def main(path, component):
    names = {}

    with open(path, encoding="utf-8") as messages:
        for line in messages:
            message = json.loads(line)
            if message.get("reason") != "compiler-artifact" or not message["profile"]["test"]:
                continue
            if message["executable"] is None:
                continue

            # a library's target name has '_' for the package's '-'
            target = message["target"]["name"]
            name = f"test-{component}"
            if target.replace("-", "_") != component.replace("-", "_"):
                name += f"-{target}"

            if name in names:
                sys.exit(f"{sys.argv[0]}: {names[name]} and {message['executable']} would both be {name}")
            names[name] = message["executable"]

    for name, executable in names.items():
        print(name, executable)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <messages.json> <component name>")
    main(*sys.argv[1:])
