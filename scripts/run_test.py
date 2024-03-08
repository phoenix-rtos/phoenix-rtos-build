#!/usr/bin/env python3
import subprocess
import argparse
import sys
import os
from typing import Dict, List

import yaml
from colorama import Fore, Style

"""
A script to run unity and pytest tests in a host environment for Phoenix-RTOS.

Example of usage:

    TARGET=host-generic-target ./phoenix-rtos-build/scripts/run_tests.py

    Options:
    - c - Set path to config
    - f - Run full test campaign
    - v - Enable verbose mode
    - S - Stream the output of test on stdout

Example of config file:

    unity: [binary1, binary2...]
    pytest:
        - "path1 args"
        - "path2"
    full_ci_unity: [binary1, binary2...]
    full_ci_pytest:
        - "path1 args"
        - "path2"

NEED TO KNOW:

    Need vm.map_rnd_bits set to 28
    You can use: sudo sysctl vm.mmap_rnd_bits=28
    due to the issue reported here: https://github.com/phoenix-rtos/phoenix-rtos-project/issues/1032
"""


class TestSetupError(Exception):
    pass


def print_fancy(message: str, color: str, flush: bool = False, end: str = "\n") -> None:
    """Prints a message with the specified color."""
    print(f"{color}{message}{Style.RESET_ALL}", flush=flush, end=end)


def run_test(test: List[str] | str, stream: bool) -> int:
    """Executes a single test command"""
    test_msg = test[-1].split(" ")[0] if isinstance(test, list) else test
    test_cmd = test if isinstance(test, str) else [cmd for item in test for cmd in item.split()]

    print_fancy(f"Running {test_msg}: ", Fore.MAGENTA, flush=True, end="\n" if stream else "")

    if stream:
        result = subprocess.run(test_cmd, text=True)
        print_fancy(f"Running {test_msg}: ", Fore.MAGENTA, flush=True, end="")
    else:
        result = subprocess.run(test_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    output = (result.stdout or result.stderr or "").strip()
    status = "FAIL" if result.returncode != 0 or output.endswith("FAIL") else "OK"

    if status == "FAIL":
        print_fancy(status, Fore.RED)
        print_fancy("OUTPUT:", Fore.YELLOW)
        print(output)
    else:
        print_fancy(status, Fore.GREEN)

    return result.returncode

# Stages

def parse_args() -> argparse.Namespace:
    """Parses script arguments"""
    parser = argparse.ArgumentParser(
        description="Run tests with options:",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--config", default="run_tests.yaml", help="Set path to config.")
    parser.add_argument("-f", "--full", action="store_true", help="Run full test campaign.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
    parser.add_argument("-S", "--stream", action="store_true", help="Stream the output of test on stdout.")
    return parser.parse_args()


def get_target() -> str:
    target = os.environ.get("TARGET")
    if not target:
        raise TestSetupError("TARGET environment variable is not set.")
    return target


def read_yaml_config(yaml_path: str, full: bool = False) -> dict:
    """Loads test configurations from YAML files"""
    try:
        with open(yaml_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
    except Exception as e:
        raise TestSetupError(f"Error reading config file: {e}")

    yaml_key = "full_ci_" if full else ""

    config_dirs = {
        'pytest': config.get(f"{yaml_key}pytest", []),
        'unity': config.get(f"{yaml_key}unity", [])
    }

    return config_dirs


def run_tests(config: Dict[str, List[str]], target: str, verbose: bool, stream: bool) -> Dict[str, int]:
    """Executes the specified tests"""
    exit_codes = {}
    for test_type, tests in config.items():
        print_fancy(f"- Start {test_type} tests -", Fore.YELLOW)
        for test in tests:
            test_cmd = ["pytest", test] if test_type == "pytest" else [f"_build/{target}/prog.stripped/{test}"]
            if test_type == "pytest" and not verbose:
                test_cmd.insert(1, "--tb=no")
            exit_codes[test] = run_test(test_cmd, stream)
            if exit_codes[test] != 0:
                print_fancy(f"{test} exit with: {exit_codes[test]}", Fore.RED)
        print_fancy(f"- {test_type.capitalize()} tests completed -", Fore.YELLOW)
    return exit_codes


def main():
    try:
        args = parse_args()
        target = get_target()
        config = read_yaml_config(args.config, args.full)

        failed_tests = run_tests(config, target, args.verbose, args.stream)
        if any(code != 0 for code in failed_tests.values()):
            if args.verbose:
                print_fancy(f"Failed tests: {failed_tests}", Fore.RED)
            return 1

    except TestSetupError as e:
        print_fancy(str(e), Fore.RED)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
