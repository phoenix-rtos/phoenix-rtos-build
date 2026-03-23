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
import sys
import resolvelib

from .port_manager import PortManager


def main() -> None:
    try:
        pm = PortManager(sys.argv)
        pm.run_cmd()
    except resolvelib.resolvers.ResolverException:
        pass


if __name__ == "__main__":
    main()
