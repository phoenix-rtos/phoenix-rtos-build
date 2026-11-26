#
# Python build core
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
from collections.abc import Sequence

import re

from collections import deque

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box


from typing import IO


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

    BOLD = "\033[1m"
    END = "\033[0m"

    BOLD_RED = "\033[1;31m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"


logger_instance = None


def create_log_panel(log_lines: Sequence[str], title: str = "", no_wrap=True):
    """Takes the current log lines and formats them into a rich-text panel"""
    text = Text("\n".join(log_lines), no_wrap=no_wrap, overflow="ellipsis")
    return Panel(text, box=box.SIMPLE, title=title)


gcc_diag_pattern = re.compile(
    r'^(.*?):(\d+):(?:(\d+):)?\s+'
    r'(warning|error|fatal error|note):\s+'
    r'(.*?)(?:\s*\[(-W[^\]]+)\])?$'
)


gcc_diag_colors = {
    "warning": Color.BOLD_MAGENTA,
    "error": Color.BOLD_RED,
    "fatal error": Color.BOLD_RED,
    "note": Color.BOLD_CYAN,
}


def render_process_log(stdout: IO[str], max_last_lines: int, skip: int = 0):
    last_lines: deque[str] = deque(maxlen=max_last_lines)
    err_lines: deque[str] = deque(maxlen=20)

    try:
        for _ in range(skip + 1):
            first_log = next(stdout)
            last_lines.append(first_log)
    except StopIteration:
        return

    with Live(refresh_per_second=60) as live:
        for line in stdout:
            line = line.rstrip()
            m = gcc_diag_pattern.match(line)
            if m:
                file, line_no, col_no, level, msg, flag = m.groups()

                color = gcc_diag_colors.get(level, "")
                flag = f"[{color}{flag}{Color.END}]" if flag else ""

                colorized = (
                    f"{Color.BOLD}{file}:{line_no}:{col_no or ''} "
                    f"{color}{level}:{Color.END} {msg} {flag}"
                )

                err_lines.append(colorized)
            else:
                last_lines.append(line)

            panels = []
            if err_lines:
                panels.append(create_log_panel(err_lines, no_wrap=False))
            if last_lines:
                panels.append(create_log_panel(last_lines))
            live.update(Group(*panels))


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
