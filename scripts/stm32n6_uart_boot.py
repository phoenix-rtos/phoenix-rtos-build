#!/usr/bin/env python3
#
# Boot STM32N6 via UART
#
# Copyright 2025 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import serial, argparse, struct, os, logging, sys, math
from typing import BinaryIO
from pathlib import Path
from enum import Enum

#### CODES
ACK = bytes([0x79])
ACK_ACK = bytes([0x79, 0x79])
NACK = bytes(0x1F)
BEGIN = bytes([0x7F])

# Commands together with complement bytes
CMD_GET = bytes([0x00, 0xFF])
CMD_GETVER = bytes([0x01, 0xFE])
CMD_GET_ID = bytes([0x02, 0xFD])
CMD_GET_PHASE = bytes([0x03, 0xFC])
CMD_WRITE_MEM = bytes([0x31, 0xCE])
CMD_READ_PART = bytes([0x12, 0xED])
CMD_START = bytes([0x21, 0xDE])

ALL_COMMANDS = [CMD_GET, CMD_GETVER, CMD_GET_ID, CMD_GET_PHASE, CMD_WRITE_MEM, CMD_READ_PART, CMD_START]


class AckException(Exception):
    def __init__(self, function: str):
        super().__init__(f"{function}: missing ACK response")


class Color(Enum):
    DEFAULT = "\033[39m"
    MAGENTA = "\033[95m"
    LBLUE = "\033[94m"
    LCYAN = "\033[96m"
    LGREEN = "\033[92m"
    YELLOW = "\033[93m"
    LRED = "\033[91m"
    ENDC = "\033[0m"


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: Color.LCYAN,
        logging.ERROR: Color.LRED,
        logging.DEBUG: Color.YELLOW,
    }

    def extra_info(self, record: logging.LogRecord) -> str:
        match record.levelno:
            case logging.ERROR:
                return f"[{record.filename}: line {record.lineno}] "
            case _:
                return ""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return f"{self.COLORS.get(record.levelno, Color.DEFAULT).value}{message}{Color.ENDC.value}"


class ProgLogger(logging.Logger):
    def __init__(self, *args, progress_bar_width: int = 50, **kwargs):
        super().__init__(*args, **kwargs)
        self.width = progress_bar_width
        self.progress_level = logging.NOTSET

    def setProgressLevel(self, progress_level: int):
        """Sets the required level for logging progress bars"""
        self.progress_level = progress_level

    # Only stream handlers make sense for the progress bar
    def progress_init(self):
        if not self.isEnabledFor(self.progress_level):
            return
        for handler in self.handlers:
            if isinstance(handler, logging.StreamHandler):
                print(f"{Color.LBLUE.value}[{" " * self.width}]{Color.ENDC.value}", end="", file=handler.stream)
                print("\x1b[1G", end="", file=handler.stream)
                sys.stdout.flush()

    def progress(self, progress: float):
        if not self.isEnabledFor(self.progress_level):
            return
        for handler in self.handlers:
            if self.isEnabledFor(logging.INFO) and isinstance(handler, logging.StreamHandler):
                count: int = math.ceil(self.width * progress)
                print("\x1b[2G", end="", file=handler.stream)
                print(f"{Color.LGREEN.value}{"=" * count}{Color.ENDC.value}", end="", file=handler.stream)
                sys.stdout.flush()

    def progress_end(
        self,
    ):
        if not self.isEnabledFor(self.progress_level):
            return
        for handler in self.handlers:
            print("\x1b[1G", end="", file=handler.stream)
            mess = "Loading successful!"
            print(
                f"{Color.LGREEN.value}{mess}{(self.width + 2 - len(mess)) * " "}{Color.ENDC.value}",
                end="\n",
                file=handler.stream,
            )


# SCRIPT ARGUMENTS:
# uart_boot.py -i <image-path> [-v -h] [-d --device <serial port device>]
# -i --image: file path to plo image to load
# -v --verbose: enable verbose debug messages
# -d --device: a serial port device path ex. /dev/ttyACM0
def parse_args():
    parser = argparse.ArgumentParser(description="Perform Serial Boot via UART on STM32N6")
    parser.add_argument("-i", "--image", required=True, type=Path, help="Specify the image file to load via Boot ROM")
    parser.add_argument("-d", "--device", default="/dev/ttyACM0", help="Select serial port device")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable terminal output")
    parser.add_argument("-dbg", "--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()


TO_STRING = {int.from_bytes(ACK): "ACK", int.from_bytes(NACK): "NACK"}


def b2str(byte_arr: bytes) -> str:
    return ", ".join([TO_STRING.get(byte, f"{hex(byte)}") for byte in byte_arr])


def validate_cmdset(avail_cmds: bytes):
    for cmd_byte, _ in ALL_COMMANDS:
        if cmd_byte not in avail_cmds:
            raise Exception(f"get: Command with code {cmd_byte} is not available.")


def calc_checksum(byte_arr: bytes) -> bytes:
    res = 0x00
    for byte in byte_arr:
        res ^= byte
    return bytes([res])


def sp_write(sp: serial.Serial, b: bytes, logger: ProgLogger):
    sp.write(b)
    logger.debug(f"write 0x{b.hex()}")


#### BOOTROM COMMANDS
def cmd_get(sp: serial.Serial, logger: ProgLogger) -> None:
    logger.debug("GET:")
    sp_write(sp, CMD_GET, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("get")

    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("get")

    num_commands = response[0] + 1
    ver = f"{(response[1] & 0xF0) >> 4}.{response[1] & 0xF}"
    avail_cmds = response[2:]

    logger.debug(f"Num of commands: {num_commands}")
    logger.info(f"Protocol version: {ver}")
    validate_cmdset(avail_cmds)
    logger.debug(f"Commands validated!")


def cmd_getver(sp: serial.Serial, logger: ProgLogger) -> None:
    logger.debug("GET VERSION:")
    sp_write(sp, CMD_GETVER, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getver")

    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("getver")

    ver = f"{response[0] & 0x2}.{response[0] & 0x1}"
    logger.debug(f"Protocol version: {ver}")


def cmd_getid(sp: serial.Serial, logger: ProgLogger) -> None:
    logger.debug("GET ID:")
    sp_write(sp, CMD_GET_ID, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getid")

    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("getid")

    pid = (response[0] << 4) | response[1]
    logger.info(f"Device ID: {pid}")


def cmd_getphase(sp: serial.Serial, logger: ProgLogger) -> tuple[int, bytes]:
    logger.debug("GET PHASE:")
    sp_write(sp, CMD_GET_PHASE, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getphase")

    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("getphase")

    phase = response[1]
    address = response[5:1:-1]
    return phase, address


# Download command
def cmd_writemem(sp: serial.Serial, packet_num: int, data: bytes, logger: ProgLogger):
    logger.debug("WRITE MEMORY:")
    sp_write(sp, CMD_WRITE_MEM, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("writemem")

    if packet_num >= 0xF2:
        raise Exception("writemem: tried to write OTP")

    packetid = struct.pack(">I", packet_num)
    sp_write(sp, packetid + calc_checksum(packetid), logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"writemem, packet: {packet_num}")

    if len(data) > 256:
        raise Exception("writemem: packet too long")

    size = len(data) - 1
    buf = bytes([size]) + data
    sp_write(sp, buf + calc_checksum(buf), logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"writemem, packet: {packet_num}")


def download_image(sp: serial.Serial, imgf: BinaryIO, logger: ProgLogger):
    logger.info(f"Loading image...")
    logger.progress_init()
    if imgf.seekable():
        imgsize = imgf.seek(0, os.SEEK_END)
        imgf.seek(0, os.SEEK_SET)
    else:
        imgsize = None

    last_progress = 0.0
    counter = 0
    while True:
        part = imgf.read(256)
        if not part:
            break
        cmd_writemem(sp, counter, part, logger)
        counter += 1

        if imgsize is not None:
            if ((counter * 256) / imgsize) > last_progress + 0.03:
                last_progress = (counter * 256) / imgsize
                logger.progress(last_progress)

    logger.progress_end()


def cmd_start(sp: serial.Serial, start_addr: int, logger: ProgLogger):
    logger.debug("START:")
    sp_write(sp, CMD_START, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("start")

    jmp_addr = struct.pack(">I", start_addr)
    sp_write(sp, jmp_addr + calc_checksum(jmp_addr), logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("start")


# Reads the certificate of the device
def cmd_readpart(sp: serial.Serial, offset: int, rsize: int, logger: ProgLogger) -> bytes:
    logger.debug("READ PARTITION:")
    sp_write(sp, CMD_READ_PART, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("readpart")

    buf = struct.pack(">B", 0xF3) + struct.pack(">I", offset)
    sp_write(sp, buf + calc_checksum(buf), logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"readpart, off: {offset}")

    size_bytes = struct.pack(">B", min(255, rsize - 1))
    buf = size_bytes + bytes([int.from_bytes(size_bytes) ^ 0xFF])
    sp_write(sp, buf, logger)

    response = sp.read(1)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"readpart, offset: {offset}")

    return sp.read(rsize)


def handshake(sp: serial.Serial, logger: ProgLogger) -> None:
    sp_write(sp, BEGIN, logger)
    response = sp.read(2)
    logger.debug(f"recv {b2str(response)}")
    if response != ACK_ACK and response != ACK:
        raise AckException("handshake")


def configure_logger() -> ProgLogger:
    logging.setLoggerClass(ProgLogger)
    logger: ProgLogger = logging.getLogger(__name__)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter("%(message)s"))
    logger.addHandler(handler)
    logger.setProgressLevel(logging.INFO)
    return logger


def perform_serial_boot(sp: serial.Serial, fsbl_image: BinaryIO, logger: ProgLogger) -> None:
    logger.info("===== UART BOOT =====")
    handshake(sp, logger)
    cmd_get(sp, logger)
    cmd_getid(sp, logger)
    download_image(sp, fsbl_image, logger)
    cmd_start(sp, 0xFFFFFFFF, logger)
    logger.info("=====================")


def main() -> None:
    logger = configure_logger()
    try:
        args = parse_args()
        if args.debug:
            logger.setLevel(logging.DEBUG)
        elif args.verbose:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.CRITICAL)

        with (
            serial.Serial(
                port=args.device,
                baudrate=115200,
                parity=serial.PARITY_EVEN,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS,
                timeout=2,
            ) as sp,
            open(args.image, "rb") as fsbl_image,
        ):
            perform_serial_boot(sp, fsbl_image, logger)

    except AckException as ackerr:
        logger.error(f"{ackerr}. Try resetting the device. The image could also be signed incorrectly.")
    except Exception as err:
        logger.error(err)


if __name__ == "__main__":
    main()
