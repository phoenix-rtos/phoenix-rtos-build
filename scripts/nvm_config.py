#
# Non-Volatile Memory configuration file handler (YAML format).
#
# Copyright 2024 Phoenix Systems
# Author: Marek Bialowas
#
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, List, Optional

import yaml


class PartitionType(Enum):
    """ptable partition type definition - keep in sync with libptable/ptable.h"""
    RAW = 0x51
    JFFS2 = 0x72
    METERFS = 0x75

    @classmethod
    def _missing_(cls, value):
        """Makes it possible to initialize class from name-as-a-string"""
        if isinstance(value, str):
            value = value.upper()
            if value in dir(cls):
                return cls[value]

        raise ValueError(f"{value} is not a valid {cls.__name__}")


@dataclass
class Partition:
    """Single partition specification"""
    offs: int
    size: int
    name: str
    type: PartitionType

    flash: Any = field(kw_only=True)  # access to the parent flash metadata
    virtual: bool = field(default=False, kw_only=True)  # don't put this partition into ptable
    empty: bool = field(default=False, kw_only=True)    # don't search for partition image when creating disk file

    def __str__(self):
        def flags(self) -> str:
            if self.virtual:
                return 'E'
            return ' '

        return f"{flags(self)} {self.offs:#08x}  {self.size:#08x}  [{int(self.size / 1024):5d} kB]   {self.name:12s} {self.type.name.lower()}"

    @property
    def filename(self):
        if self.virtual:
            return f"part_{self.flash.name}_{self.name}.img"

        return f"part_{self.name}.img"


@dataclass
class FlashMemory:
    """Single flash memory specification"""
    name: str
    size: int
    block_size: int
    padding_byte: int = 0x0

    parts: List[Partition] = field(default_factory=list, kw_only=True)

    @property
    def ptable_filename(self):
        return f"{self.name}.ptable"

    def validate(self):
        """Sanity checks for memory layout"""
        prev_part = None
        part_names = set()
        for part in self.parts:
            if part.name in part_names:
                raise ValueError(f"{self.name}: duplicate partition name '{part.name}'")

            part_names.add(part.name)

            if part.virtual:  # virtual partitions can overlap existing ones and not be aligned to block
                continue

            if part.offs % self.block_size != 0:
                raise ValueError(f"{self.name}: partition '{part.name}' start 0x{part.offs:x} is not aligned to block size 0x{self.block_size:x}")
            if part.size % self.block_size != 0:
                raise ValueError(f"{self.name}: partition '{part.name}' size 0x{part.size:x} is not aligned to block size 0x{self.block_size:x}")

            if prev_part and part.offs < prev_part.offs:
                raise ValueError(f"{self.name}: partition offsets are not monotonic (error at {part.name})")
            if prev_part and part.offs < (prev_part.offs + prev_part.size):
                raise ValueError(f"{self.name}: partitions '{part.name}' and '{prev_part.name}' are overlapping")

            if part.offs + part.size > self.size:
                raise ValueError(f"{self.name}: partition '{part.name}' size extends over the end of the flash")

            prev_part = part

        if prev_part and (free_size := self.size - (prev_part.offs + prev_part.size)) > 0:
            logging.debug(f"{self.name}: free space at the end: 0x{free_size:x} [{int(free_size / 1024)} kB]")

    def __str__(self):
        return f"{self.__class__.__name__}({self.name})  size={self.size:#x} [{int(self.size / 1024 / 1024)} MB] block_size={self.block_size:#x}\n" \
            + "\n".join(["\t" + str(p) for p in self.parts])


def round_up(size: int, size_page: int) -> int:
    return (size + size_page - 1) & ~(size_page - 1)


def read_nvm(fname: str) -> List[FlashMemory]:
    """reads full Non-Volatile Memory layout from a file {fname}"""
    nvm = []
    with open(fname, "r", encoding="utf-8") as fin:
        nvm_dict = yaml.safe_load(fin)
        # TODO: validate against JSON template?

        for (name, attrs) in nvm_dict.items():
            f = FlashMemory(name, attrs['size'], attrs['block_size'], attrs.get('padding_byte', 0))
            curr_offs = 0
            prev_p: Partition | None = None
            for part_attrs in attrs.get('partitions', []):
                p = Partition(part_attrs.get('offs', curr_offs), part_attrs.get('size', 0), part_attrs['name'],
                              PartitionType(part_attrs.get('type', 'RAW')), flash=f, empty=part_attrs.get('empty', False))

                if part_attrs.get('virtual'):
                    p.virtual = True
                else:
                    curr_offs = round_up(p.offs + p.size, f.block_size)

                # set previous partition size from the absolute offset of the current one
                if not p.virtual and 'offs' in part_attrs and prev_p is not None and prev_p.size == 0:
                    prev_p.size = p.offs - prev_p.offs

                f.parts.append(p)
                prev_p = p

            # add "virtual" ptable partition
            ptable_blocks = attrs.get('ptable_blocks', 0)
            if ptable_blocks > 0:
                ptable_size = ptable_blocks * f.block_size
                p = Partition(f.size - ptable_size, ptable_size, "ptable", PartitionType.RAW, flash=f, virtual=True)
                f.parts.append(p)

            # set last non-virtual partition size (if 0) to the end of flash
            for part in reversed(f.parts):
                if not part.virtual:
                    if part.size == 0:
                        part.size = f.size - part.offs
                    break

            logging.debug(f)
            f.validate()
            nvm.append(f)

    return nvm


def find_target_part(nvm: List[FlashMemory], name: str) -> Optional[Partition]:
    """Finds matching partition from name in format `[flash_name:]part_name`"""
    part_name = name
    flash_name = None
    if ":" in part_name:
        (flash_name, part_name) = part_name.split(":")

    for flash in nvm:
        if flash_name is not None and flash.name != flash_name:
            continue

        for part in flash.parts:
            if part.name == part_name:
                return part

    return None
