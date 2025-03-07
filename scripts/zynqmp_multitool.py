#!/usr/bin/env python3

"""
A script to automate some tasks when flashing Zynq Ultrascale+ devices

This is a very WIP script and relies on having a RAM disk at device 4.0 in plo
"""

import argparse
import os
import subprocess

import serial
import nvm_config
from typing import Any, Callable, Dict, Iterable, List
from pathlib import Path

RAMDISK_DEVICE = "4.0"
RAMDISK_OFFSET = 0x08000000
OPENOCD_PATH = Path("/usr/bin/openocd")
SCRIPT_DIR = Path(__file__).parent
REPO_DIR = Path(__file__).parent.parent.parent
SCRIPTS_PATH = SCRIPT_DIR / "zynqmp_openocd"

CHOICE_ADAPTER = ["zcu104", "xmod"]
ADAPTER_SCRIPT = {
    "zcu104": "ftdi_zcu104.cfg",
    "xmod": "ftdi_te0790.cfg",
}
CHOICE_SYSTEM = ["zcu104", "som"]
SYSTEM_SCRIPT = {
    "zcu104": "xilinx_zynqmp.cfg",
    "som": "xilinx_zynqmp.cfg",
}
DEFAULT_ADAPTER = {"zcu104": "zcu104", "som": "xmod"}

OPENOCD_COMMON = [
    # fmt: off
    "{OPENOCD_PATH}",
    "-f", '{ADAPTER_CFG}',
    "-c", 'adapter speed 24000',
    "-f", '{SYSTEM_CFG}',
    "-c", 'reset_config srst_only',
    # fmt: on
]


def parse_args():
    parser = argparse.ArgumentParser(description="ZynqMP multitool")
    parser.add_argument("-s", "--system", type=str, choices=CHOICE_SYSTEM, required=True)
    parser.add_argument("-p", "--serial", type=Path, help="Path to serial port")
    parser.add_argument("-a", "--adapter", type=str, choices=CHOICE_ADAPTER, help="JTAG adapter (if not selected, default for system will be chosen)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Simple interactive mode")
    parsed = parser.parse_args()
    if parsed.adapter is None:
        parsed.adapter = DEFAULT_ADAPTER[parsed.system]

    return parsed


def run_cmd(args, extra: Dict[str, Any], cmd_str: List[str], *vargs, **kwargs):
    fmt = {
        "OPENOCD_PATH": OPENOCD_PATH,
        "ADAPTER_CFG": SCRIPTS_PATH / ADAPTER_SCRIPT[args.adapter],
        "SYSTEM_CFG": SCRIPTS_PATH / SYSTEM_SCRIPT[args.system],
        **extra,
    }

    return subprocess.run([x.format(**fmt) for x in cmd_str], check=True, *vargs, **kwargs)


def make_openocd_cmd(commands: List[str], do_exit=True):
    ret = [*OPENOCD_COMMON, "-c", "init"]
    for x in zip(["-c"] * len(commands), commands):
        ret.extend(x)

    if do_exit:
        ret.extend(("-c", "exit"))

    return ret


def reset_halt_apus(args):
    return run_cmd(args, {}, make_openocd_cmd(["reset_apus", "start_apu 0"]))


def soft_por(args):
    return run_cmd(args, {}, make_openocd_cmd(["soft_por"]))


def run_plo_ram(args):
    extra = {"FILE_PATH": REPO_DIR / f"_boot/aarch64a53-zynqmp-pilot/plo-ram.img"}
    reset_halt_apus(args)
    return run_cmd(args, extra, make_openocd_cmd(['boot_apu "{FILE_PATH}"']))


def copy_to_ramdisk(args, file: Path):
    cmd_copy_to_ramdisk = [
        "halt",
        'load_image "{FILE_PATH}" {RAMDISK_OFFSET} bin',
        "resume",
    ]
    extra = {
        "FILE_PATH": file,
        "RAMDISK_OFFSET": RAMDISK_OFFSET,
    }
    return run_cmd(args, extra, make_openocd_cmd(cmd_copy_to_ramdisk))


def get_partitions(args):
    parts: List[nvm_config.Partition] = []
    nvms = nvm_config.read_nvm(REPO_DIR / f"_projects/aarch64a53-zynqmp-{args.system}/nvm.yaml")
    for nvm in nvms:
        parts.extend(nvm.parts)

    return parts


def copy_partition(args, part: nvm_config.Partition):
    filename = REPO_DIR / f"_boot/aarch64a53-zynqmp-{args.system}/{part.filename}"
    size = os.stat(filename).st_size
    copy_command = f"copy ramdisk 0 {size} {part.flash.name} {part.offs} {size}\n"
    if not args.serial:
        raise ValueError("Serial port not set")

    copy_to_ramdisk(args, filename)
    with serial.Serial(str(args.serial), baudrate=115200, timeout=0.5) as ser:
        ser.write(copy_command.encode())
        if not args.interactive:
            # In interactive mode we assume user has terminal connected to serial port
            # so reading from port would result in errors
            # TODO: read and check for command completion
            pass


class Action:
    def __init__(self, name: str, fn: Callable, fn_args: List[Any]):
        self.name = name
        self.fn = fn
        self.fn_args = fn_args

    def do(self, args):
        self.fn(args, *self.fn_args)


class StateAction(Action):
    def __init__(self, name, fn, fn_args):
        super().__init__(name, fn, fn_args)


def make_copy_partition_actions(parts: Iterable[nvm_config.Partition]):
    return [Action(f"Copy {x.flash.name}:{x.name} to device", copy_partition, [x]) for x in parts]


def read_temperature(args):
    addr_str = "0xffa50800"
    process = run_cmd(args, {}, make_openocd_cmd([f"puts [uscale.axi mdw {addr_str}]"]), capture_output=True)
    if isinstance(process.stdout, bytes):
        adc_value = int(process.stdout.decode("ascii", "ignore").split(f"{addr_str}:")[1].strip(), 16)
    else:
        raise ValueError(f"No output from process")

    # UltraScale Architecture System Monitor (UG580), Equation 2‐11
    return adc_value * 509.3140064 / (1 << 16) - 280.23087870


def print_temperature(args):
    temp = read_temperature(args)
    print(f"TEMP_LPD: {temp:.1f}°C")


def repl_mode(args):
    parts = get_partitions(args)
    actions = [
        Action("Reset and halt APUs", reset_halt_apus, []),
        Action("Start PLO from RAM", run_plo_ram, []),
        *make_copy_partition_actions(parts),
        Action("Soft POR reset", soft_por, []),
        Action("Get device temperature", print_temperature, []),
    ]

    while True:
        for idx, act in enumerate(actions):
            print(idx, "=>", act.name)

        action = input("Select action: ")
        idx = int(action)
        actions[idx].do(args)


if __name__ == "__main__":
    args = parse_args()
    if args.interactive:
        repl_mode(args)
    else:
        # TODO: batch mode
        pass
