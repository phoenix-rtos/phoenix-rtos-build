#
# Log utility for STM32N6 scripts
#
# Copyright 2023 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import sys, math

DEBUG_LOG_ENABLED = False

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def error(mess: str) -> None:
    info_log(mess, bcolors.FAIL)
    exit(1)


def hex2bytes(hexstr: str) -> bytes:
    hexstr = "".join(hexstr.split())
    return bytes([int(hexstr[i] + hexstr[i + 1], 16) for i, x in enumerate(hexstr) if i % 2 == 0])


def bytes2hex(data: bytes) -> str:
    return "".join([f"{b:02x}" for b in data])


def b2chr(i: int) -> str:
    c = chr(i)
    if c.isalnum():
        return c
    else:
        return '.'


def log_bytes(data: bytes):
    for i, b in enumerate(data):
        if i % 8 == 0:
            print(f"\n{bcolors.HEADER}0x{i:08X}{bcolors.ENDC}", end=" ")
        print(f"{b:02x} ", end="")
        

def debug_log(mess: str, marker: bcolors = None) -> None:
    if DEBUG_LOG_ENABLED:
        if marker == None:
            marker = marker_end = ""
        else:
            marker_end = bcolors.ENDC
        print(f"{marker}{mess}{marker_end}")


def info_log(mess: str, marker: bcolors = None, end="\n"):
    if marker == None:
        marker = marker_end = ""
    else:
        marker_end = bcolors.ENDC
    print(f"{marker}{mess}{marker_end}", end=end)


def log_progress_init(width: int):
    info_log(f"[{" " * width}]", bcolors.OKCYAN, "")
    print("\x1b[1G", end="")
    sys.stdout.flush()


def log_progress(width: int, progress: float):
    count: int = math.ceil(width * progress)
    print("\x1b[2G", end="")
    info_log(f"{"=" * count}", bcolors.OKGREEN, "")
    sys.stdout.flush()


def log_progress_end(width: int):
    print("\x1b[1G", end="")
    mess = "Loading sucessful!"
    info_log(f"{mess}{(width + 2 - len(mess)) * " "}", bcolors.OKCYAN)


def check_bin_file(file_path: str):
    try:
        f = open(file_path, 'rb')
        f.close()
    except FileNotFoundError:
        error(f"ERROR: {file_path} file not found")
    except Exception as e:
        error(f"ERROR: {e} error while opening {file_path}")

