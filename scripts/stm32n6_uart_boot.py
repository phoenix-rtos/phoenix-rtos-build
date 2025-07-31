#!/usr/bin/env python3
#
# Boot STM32N6 via UART
#
# Copyright 2025 Phoenix Systems
# Author: Krzysztof Radzewicz
#

import serial, traceback, argparse, struct, os
from stm32n6_log_util import *


SERIAL_DEVICE = ""


#### CODES
ACK = bytes([0x79]) 
ACK_ACK = bytes([0x79, 0x79])
NACK = bytes(0x1F)
BEGIN = bytes([0x7F])

CMD_GET = bytes([0x00, 0xFF])
CMD_GETVER = bytes([0x01, 0xFE])
CMD_GET_ID = bytes([0x02, 0xFD])
CMD_GET_PHASE = bytes([0x03, 0xFC])
CMD_WRITE_MEM = bytes([0x31, 0xCE])
CMD_READ_PART = bytes([0x12, 0xED])
CMD_START = bytes([0x21, 0xDE])


class AckException(Exception):
    def __init__(self, function: str):
        super().__init__(f"{function}: missing ACK response")


# SCRIPT ARGUMENTS:
# uart_boot.py -i <image-path> [-v -h] [-d --device <serial port device>]
# -i --image: file path to plo image to load
# -v --verbose: enable verbose debug messages
# -d --device: a serial port device path ex. /dev/ttyACM0
def parse_args():
    parser = argparse.ArgumentParser(description="Perform Serial Boot via UART on STM32N6")
    parser.add_argument("-i", "--image", required=True, help="Specify the image file to load via Boot ROM")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--device", default="/dev/ttyACM0", help="Select serial port device")
    args = parser.parse_args()
    global DEBUG_LOG_ENABLED
    DEBUG_LOG_ENABLED = args.verbose
    try:
        f = open(args.image, 'rb')
        f.close()
    except FileNotFoundError:
        info_log(f"ERROR: {args.image} file not found", bcolors.WARNING)
        exit(1)
    except Exception as e:
        info_log(f"ERROR: unknown error while opening {args.image}", bcolors.WARNING)
        exit(1)
    
    return args


TO_STRING = {int.from_bytes(ACK): "ACK", int.from_bytes(NACK): "NACK"}
def b2str(byte_arr: bytes) -> str:
    return ", ".join([TO_STRING.get(byte, f"{hex(byte)}") for byte in byte_arr])


def validate_cmdset(avail_cmds: bytes) -> int:
    for c in bytes([0x0, 0x1, 0x2, 0x3, 0x12, 0x12, 0x21, 0x31]):
        if c not in avail_cmds:
            raise Exception(f"get: Command with code {c} is not available.")


def calc_checksum(byte_arr: bytes) -> bytes:
    res = 0x00
    for byte in byte_arr:
        res ^= byte
    return bytes([res])


def sp_write(sp: serial.Serial, b: bytes):
    sp.write(b)


#### BOOTROM COMMANDS
def cmd_get(sp: serial.Serial, verbose: bool = True) -> None: 
    debug_log("GET:")
    sp_write(sp, CMD_GET)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("get")

    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("get")

    num_commands = response[0] + 1
    ver = f"{(response[1] & 0xF0) >> 4}.{response[1] & 0xF}"
    avail_cmds = response[2:]

    if verbose:
        debug_log(f"Num of commands: {num_commands}")
        info_log(f"Protocol version: {ver}", bcolors.OKCYAN)
        validate_cmdset(avail_cmds)
        debug_log(f"Commands validated!")


def cmd_getver(sp: serial.Serial) -> None:
    debug_log("GET VERSION:")
    sp_write(sp, CMD_GETVER)
    debug_log("write 0x01 0xFE")

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getver")
    
    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("getver")

    ver = f"{response[0] & 0x2}.{response[0] & 0x1}"
    debug_log(f"Protocol version: {ver}")


def cmd_getid(sp: serial.Serial, verbose: bool = True) -> None:
    debug_log("GET ID:")
    sp_write(sp, CMD_GET_ID)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getid")
    
    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("gettid")
    
    pid = (response[0] << 4) | response[1]
    if verbose:
        info_log(f"Device ID: {pid}", bcolors.OKCYAN)


def cmd_getphase(sp: serial.Serial) -> tuple[int, bytes]:
    debug_log("GET PHASE:")
    sp_write(sp, CMD_GET_PHASE)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("getphase")
    
    response = sp.read_until(ACK)
    if bytes([response[-1]]) != ACK:
        raise AckException("getphase")
    

    phase = response[1]
    address = response[5:1:-1]
    return phase, address


# Download command
def cmd_writemem(sp: serial.Serial, packet_num: int, data: bytes) -> int:
    debug_log("WRITE MEMORY:")
    sp_write(sp, CMD_WRITE_MEM)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("writemem")
    
    if packet_num >= 0xF2:
        raise Exception("writemem: tried to write OTP")
    
    packetid = struct.pack(">I", packet_num)
    sp_write(sp, packetid + calc_checksum(packetid))
    
    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"writemem, packet: {packet_num}")
    
    if len(data) > 256:
        raise Exception("writemem: packet too long")
    
    size = len(data) - 1
    buf = bytes([size]) + data
    sp_write(sp, buf + calc_checksum(buf))

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"writemem, packet: {packet_num}")


def download_image(sp: serial.Serial, image_path: str):
    info_log(f"Loading {image_path} image...", bcolors.OKCYAN)
    log_progress_init(50)
    imgsize = os.path.getsize(image_path) / 256
    last_progress = 0
    imgf = open(image_path, "rb")
    counter = 0
    while True:
        part = imgf.read(256)
        if not part:
            break
        cmd_writemem(sp, counter, part)
        counter += 1

        if counter / imgsize > last_progress + 0.3:
            last_progress = counter / imgsize
            log_progress(50, last_progress)

    imgf.close()
    log_progress_end(50)


def cmd_start(sp: serial.Serial, start_addr: int):
    debug_log("START:")
    sp_write(sp, CMD_START)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("start")

    jmp_addr = struct.pack(">I", start_addr)
    sp_write(sp, jmp_addr + calc_checksum(jmp_addr))

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("readpart")


# Reads the certificate of the device
def cmd_readpart(sp: serial.Serial, offset: int, rsize: int) -> bytes:
    debug_log("READ PARTITION:")
    sp_write(sp, CMD_READ_PART)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException("readpart")
    
    buf = struct.pack(">B", 0xF3) + struct.pack(">I", offset)
    print(f"buf1: {buf}")
    sp_write(sp, buf + calc_checksum(buf))
    
    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"readpart, off: {offset}")
    
    size_bytes = struct.pack(">B", min(255, rsize - 1))
    buf = size_bytes + bytes([int.from_bytes(size_bytes) ^ 0xFF])
    print(f"buf2: {buf}")
    sp_write(sp, buf)

    response = sp.read(size=1)
    debug_log(f"recv {b2str(response)}")
    if response != ACK:
        raise AckException(f"readpart, offset: {offset}")
    
    return sp.read(rsize)
    

def handshake(sp: serial.Serial) -> None:
    sp_write(sp, BEGIN)
    debug_log("write BEGIN")
    response = sp.read(size=2)
    debug_log(f"recv {b2str(response)}")
    if response != ACK_ACK and response != ACK:
        raise AckException("handshake")


def main() -> None:
    args = parse_args()

    sp = serial.Serial()
    sp.port = args.device
    sp.baudrate = 115200
    sp.parity = serial.PARITY_EVEN
    sp.stopbits = serial.STOPBITS_ONE
    sp.bytesize = serial.EIGHTBITS
    sp.timeout = 2

    try:
        sp.open()
        info_log("===== UART BOOT =====", bcolors.HEADER)
        handshake(sp)
        cmd_get(sp)
        cmd_getid(sp)
        download_image(sp, args.image)
        cmd_start(sp, 0xFFFFFFFF)
        info_log("=====================", bcolors.HEADER)

    except Exception as err:
        info_log(f"ERROR: {err}", bcolors.WARNING)
        trace_str = traceback.format_exc()
        info_log(trace_str, bcolors.FAIL)

    finally:
        sp.close()


if __name__ == "__main__":
    main()

