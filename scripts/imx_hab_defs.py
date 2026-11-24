#!/usr/bin/env python3
#
# Script containing definitions related to HAB ROM on IMX platforms
#
# Copyright 2026 Phoenix Systems
# Author: Jacek Maksymowicz
#

import struct
from dataclasses import dataclass, astuple


@dataclass
class ImxIvt:
    hdr: int = 0x412000d1
    entry: int = 0
    reserved1: int = 0
    dcd: int = 0
    boot_data: int = 0
    ivt_self: int = 0
    csf: int = 0
    reserved2: int = 0
    SIZE = 32

    @classmethod
    def unpack(cls, b: bytes):
        if len(b) != cls.SIZE:
            raise RuntimeError("Unexpected IVT length")

        ivt = cls(*struct.unpack("<8I", b))
        if (ivt.hdr & 0xf0ffffff) != 0x402000d1:
            raise RuntimeError(f"Unrecognized IVT header: 0x{ivt.hdr:08x}")

        if ivt.boot_data != 0:
            if ivt.boot_data < ivt.ivt_self:
                raise RuntimeError("Malformed IVT: boot data pointer lower than IVT pointer")

        if ivt.dcd != 0:
            if ivt.dcd < ivt.ivt_self:
                raise RuntimeError("Malformed IVT: DCD pointer lower than IVT pointer")

        if ivt.csf != 0:
            if ivt.csf < ivt.ivt_self:
                raise RuntimeError("Malformed IVT: CSF pointer lower than IVT pointer")

        return ivt

    def calculate_offset(self, x: int, ivt_offset: int):
        if x < self.ivt_self:
            raise ValueError("Invalid pointer given")

        return x - self.ivt_self + ivt_offset

    def pack(self):
        return struct.pack("<8I", *astuple(self))


@dataclass
class ImxBootData:
    load_addr: int
    load_size: int
    plugin: int
    SIZE = 12

    @classmethod
    def unpack(cls, b: bytes):
        if len(b) != cls.SIZE:
            raise RuntimeError("Unexpected boot data length")

        return cls(*struct.unpack("<3I", b))

    def pack(self):
        return struct.pack("<3I", *astuple(self))
