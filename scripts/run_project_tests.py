#!/usr/bin/env python3

"""
A script to run unity and pytest tests in a host environment for Phoenix-RTOS.

Example of config file:

    campaign_name:
        unity:
            - binary1 args
            - binary2
        pytest:
            - path1 args
            - path2
"""

import subprocess
import argparse
import sys
import os
from typing import Dict, List

import yaml
from colorama import Fore, init


class TestSetupError(Exception):
    pass


def run_test(test_cmd: List[str], test_name: str, stream: bool) -> int:
    """Executes a single test command"""
    print(f"{Fore.MAGENTA}Running {test_name}: ", flush=True, end="\n" if stream else "")

    if stream:
        result = subprocess.run(test_cmd, text=True)
        print(f"{Fore.MAGENTA}Running {test_name}: ", flush=True, end="")
    else:
        result = subprocess.run(test_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"{Fore.RED}FAIL")
        if not stream:
            if result.stdout:
                print(f"{Fore.YELLOW}STDOUT:")
                print(result.stdout, end='')
            if result.stderr:
                print(f"{Fore.RED}STDERR:")
                print(result.stderr, end='')
    else:
        print(f"{Fore.GREEN}OK")

    return result.returncode


def parse_args() -> argparse.Namespace:
    """Parses script arguments"""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-C", "--campaign", default="ci", help="Set campaign to run (default: %(default)s)")
    parser.add_argument("-c", "--config", default=".tests_config.yaml", help="Set path to config (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-S", "--stream", action="store_true", help="Stream the output of test on stdout")
    return parser.parse_args()


def get_target() -> str:
    target = os.environ.get("TARGET")
    if not target:
        raise TestSetupError("TARGET environment variable is not set.")
    return target


def read_yaml_config(yaml_path: str) -> dict:
    """Loads test configurations from YAML files"""
    try:
        with open(yaml_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
    except Exception as e:
        raise TestSetupError(f"Error while reading config file: {e}") from e

    return config


def run_tests(config: dict, campaign:str, target: str, verbose: bool, stream: bool) -> Dict[str, int]:
    """Executes the specified tests"""
    exit_codes = {}
    test_types = ["unity", "pytest"]

    if campaign not in config:
        raise ValueError(f"Campaign '{campaign}' not found in the config file.")

    for test_type, tests in config[campaign].items():

        if test_type not in test_types:
            raise TestSetupError(f"Unexpected test type '{test_type}' in campaign '{campaign}'. Expected {test_types}.")

        print(f"{Fore.YELLOW}- Start {test_type} tests -")

        for test in tests:
            if test_type == "pytest":
                test_cmd = ["pytest"] + test.split()
                if not verbose:
                    test_cmd.append("--tb=no")
                if verbose or stream:
                    test_cmd.append("-v")
            if test_type == "unity":
                test_cmd = [f"./_build/{target}/prog/{test}"]

            exit_codes[test] = run_test(test_cmd, test, stream)

            if exit_codes[test] != 0:
                print(f"{Fore.RED}{test} exited with: {exit_codes[test]}")

    return exit_codes


def main():
    init(autoreset=True)

    try:
        args = parse_args()
        target = get_target()
        config = read_yaml_config(args.config)

        completed_tests = run_tests(config, args.campaign, target, args.verbose, args.stream)
        if any(code != 0 for code in completed_tests.values()):
            if args.verbose:
                print(f"{Fore.YELLOW}Completed tests and their exit codes: {completed_tests}")
            return 1

    except TestSetupError as e:
        print(f"{Fore.RED}{str(e)}")
        return 1
    except Exception as e:
        print(f"{Fore.RED}Unexpected Error: {str(e)}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
