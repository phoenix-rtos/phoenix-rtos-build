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

from .port_manager import PortManager


def main() -> None:
    pm = PortManager(sys.argv)
    pm.run_cmd()


if __name__ == "__main__":
    main()
