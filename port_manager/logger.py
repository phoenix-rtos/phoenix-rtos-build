#
# Port management
#
# Logger
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations

import sys
from enum import Enum


class LogLevel(Enum):
    VERBOSE = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    NONE = 4


class Color:
    CYAN = "\033[0;36m"
    BLUE = "\033[0;34m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    END = "\033[0m"


logger_instance = None


class Logger:
    print_level: LogLevel = LogLevel.WARN

    def __init__(self) -> None:
        self.pkg_stack: list[str] = []

    def _pretty_print_pkg_scope(self, end_tree: bool) -> str:
        depth = len(self.pkg_stack)
        pkg_scope = ""
        if depth > 0:
            if depth == 1:
                pkg_scope += "└" if end_tree else "├"
            else:
                pkg_scope += "│" if depth > 1 else "├"
                pkg_scope += " " * (2 * depth - 1)
                pkg_scope += "└" if end_tree else "├"
            pkg_scope += "─" * 2 + f" [{self.pkg_stack[-1]}] "
        return pkg_scope

    def _print(
        self, fmt: str, level: LogLevel, color: str, end_tree: bool = False, **kwargs
    ) -> None:
        if level.value >= self.print_level.value:
            pkg_scope = self._pretty_print_pkg_scope(end_tree)
            print(
                color
                + f"{level.name}: "
                + Color.END
                + pkg_scope
                + fmt
                + color
                + Color.END,
                file=sys.stderr,
                **kwargs,
            )

    def nest(self, pkg: str) -> None:
        self.pkg_stack.append(pkg)

    def unnest(self) -> None:
        self.pkg_stack.pop()

    def set_level(self, n: LogLevel) -> None:
        self.print_level = n

    def debug(self, *fmt: object, sep: str = " ", **kwargs) -> None:
        self._print(
            sep.join(map(str, fmt)), level=LogLevel.VERBOSE, color=Color.GREEN, **kwargs
        )

    def info(self, *fmt: object, sep: str = " ", **kwargs) -> None:
        self._print(
            sep.join(map(str, fmt)), level=LogLevel.INFO, color=Color.CYAN, **kwargs
        )

    def warning(self, *fmt: object, sep: str = " ", **kwargs) -> None:
        self._print(
            sep.join(map(str, fmt)),
            level=LogLevel.WARN,
            color=Color.YELLOW,
            **kwargs,
        )

    def error(self, *fmt: object, sep: str = " ", **kwargs) -> None:
        self._print(
            sep.join(map(str, fmt)), level=LogLevel.ERROR, color=Color.RED, **kwargs
        )


logger = Logger()
