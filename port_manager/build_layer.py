#
# Port management
#
# Build system interaction layer
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Collection, Generator, Sequence

import os
import sys

from pathlib import Path

import subprocess

from collections import deque

import json
import jinja2
import yaml

from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box

from .logger import logger

if TYPE_CHECKING:
    from .candidates import Candidate


PORT_MGMT_DIR = Path(__file__).parent


# borrowed from phoenix-rtos-build/scripts/image_builder.py
def str_to_bool(v: str | bool) -> bool:
    """False is denoted by empty string or any literal sensible false values"""
    if not v:
        return False
    if isinstance(v, bool):
        return v
    return v.lower() not in ("", "no", "false", "n", "0")


def get_term_width() -> int:
    try:
        term_width = os.get_terminal_size().columns if sys.stdout.isatty() else 80
    except (OSError, ValueError):
        term_width = 80
    return term_width


def create_log_panel(log_lines: Sequence[str], border_style: str = "white", title: str = ""):
    """Takes the current log lines and formats them into a rich-text panel"""
    text = Text("\n".join(list(log_lines)), no_wrap=True, overflow="ellipsis")
    return Panel(text, border_style=border_style, box=box.SIMPLE, title=title)


def ensure_getenv(var: str):
    prefix = os.getenv(var)
    if prefix is None:
        raise OSError(f"{var} undefined")
    return prefix


def find_ports(ports_dir: str) -> Generator[tuple[dict[str, str], Path]]:
    """Invokes port_def_to_json.sh on *.def.sh files found under ports_dir"""
    for port_def in Path(ports_dir).rglob("*.def.sh"):
        result = subprocess.run(
            ["bash", PORT_MGMT_DIR / "port_def_to_json.sh", port_def],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error(f"during loading of {port_def}:\n{result.stdout}")
            sys.exit(1)

        dct = json.loads(result.stdout)
        logger.debug(dct)

        assert isinstance(dct, dict)
        yield (dct, port_def)


PortsToBuildDict = dict[str, bool | str | dict[str, str] | list[dict[str, str]]]


def get_ports_to_build(
    ports_yamls: str,
) -> PortsToBuildDict | None:
    """
    Reads port.yaml files from colon-separated ports_yamls. Files are first
    rendered as jinja2 templates with OS environment and a `bool` function for
    converting bool-like string environment variables to boolean, allowing
    for env-dependent configs like:
    ```
    tests: {{ bool(env.BUILD_TESTS) }} # tests built iff BUILD_TESTS is true
    ports:
    - name: foo
      use: {{ ["flag"] if bool(env.USE_FOO_FLAG) }}
      tests: True
    - name: bar
      if: {{ bool(env.BUILD_BAR) }} # bar built iff BUILD_BAR is true
    ```
    This is a behaviour somewhat similar to plo yaml scripts.
    """
    ports_to_build: PortsToBuildDict = {}
    nonempty_ports_yamls: list[str] = []

    for ports_yaml in ports_yamls.split(":"):
        if not os.path.exists(ports_yaml) or not os.path.isfile(ports_yaml):
            continue
        with open(ports_yaml, encoding="utf-8") as f:
            template = jinja2.Template(f.read())
            template.globals["bool"] = str_to_bool
            dct = yaml.safe_load(template.render(env=os.environ))
            if dct:
                nonempty_ports_yamls.append(ports_yaml)
                for k, v in dct.items():
                    if k in ports_to_build and isinstance(ports_to_build[k], list):
                        ports_to_build[k] += v
                    else:
                        ports_to_build[k] = v

    logger.info(
        "Loaded port requirements from:"
        + "".join([f"\n * {s}" for s in nonempty_ports_yamls])
    )

    return ports_to_build


def run_process(
    cmd: Sequence[str | Path],
    env: dict[str, str],
    pass_fds: Collection[int] = (),
    buf_lines: int = 5,
    border_style: str = "white",
    log_title: str = "",
    roll_logs: bool = False,
    skip: int = 0,
) -> subprocess.Popen:
    """Runs a process with given cmd. If roll_logs=True, captures the logs into
    a rolling buffer of buf_lines lines"""
    if not roll_logs:
        return subprocess.Popen(
            cmd,
            env=env,
            pass_fds=pass_fds,
            text=True,
        )

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        pass_fds=pass_fds,
        text=True,
    )

    last_lines: deque[str] = deque(maxlen=buf_lines)

    if proc.stdout:
        try:
            for _ in range(skip + 1):
                first_log = next(proc.stdout)
                last_lines.append(first_log)
        except StopIteration:
            return proc

        with Live(refresh_per_second=60) as live:
            for text in proc.stdout:
                for line in text.splitlines():
                    last_lines.append(line)
                    live.update(
                        create_log_panel(
                            last_lines, border_style=border_style, title=log_title
                        )
                    )

    return proc


def prepare_cand(
    cand: Candidate, env: dict[str, str], roll_logs: bool
) -> dict[str, str]:
    """Invokes port_prepare.sh on a candidate. Captures the resulting shell
    environment"""
    log_file_path = os.path.join(env["PREFIX_BUILD"], "prepare.log")
    r_fd, w_fd = os.pipe()

    logger.info("-> Prepare")

    proc = run_process(
        [
            "bash",
            PORT_MGMT_DIR / "port_prepare.sh",
            cand.definition_path,
            str(w_fd),
            log_file_path,
        ],
        pass_fds=(w_fd,),
        env=env,
        buf_lines=10,
        roll_logs=roll_logs,
        skip=1,  # first line is always a timestamp
    )

    if proc.wait() != 0:
        logger.error(f"Failed to prepare {cand}. Full logs written to {log_file_path}")
        sys.exit(1)

    os.close(w_fd)
    with os.fdopen(r_fd) as r:
        env_output = r.read()

    # port_prepare outputs sanitized environment for future build_cand invocation
    build_env = dict()

    for line in env_output.split("\0"):
        if "=" in line:
            key, value = line.split("=", 1)
            build_env[key] = value

    return build_env


def build_cand(cand: Candidate, env: dict[str, str], roll_logs: bool):
    """Invokes port_build.sh on a candidate"""
    log_file_path = os.path.join(env["PREFIX_PORT_BUILD"], "build.log")

    # TODO: rebuild on ports.yaml (port-local) change and patches changes
    logger.info("-> Build")

    proc = run_process(
        [
            "bash",
            str(PORT_MGMT_DIR / "port_build.sh"),
            cand.definition_path,
            log_file_path,
        ],
        env=env,
        roll_logs=roll_logs,
        skip=1,  # first line is always a timestamp
    )

    retcode = proc.wait()

    if retcode != 0:
        logger.error(f"Failed to build {cand}. Full logs written to {log_file_path}")
        sys.exit(1)
