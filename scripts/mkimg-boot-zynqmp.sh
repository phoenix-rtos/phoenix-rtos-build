#!/usr/bin/env bash
#
# Shell script for building boot layout for ZynqMP
# Based on Bootgen User Guide - UG1283 (v2018.2) September 28, 2018
#
# Copyright 2021, 2024 Phoenix Systems
# Author: Hubert Buczynski, Jacek Maksymowicz


#
# The following script creates a header for the bootloader (PLO) image.
# The boot layout can be composed of multiple partitions and images - in our case there is only one of each.
# On reset, boot ROM looks for a boot layout with this header, then loads the bootloader image into memory
# at address 0xfffc0000.
# Output image from this script can be written to QSPI flash or BOOT.BIN file on SD card.
#
# Usage:
#    $1 - path to image
#    $2 - path to output image
#    $3 - image entrypoint in memory
#
#    example: ./mkimg-boot-zynqmp.sh plo-aarch64a53-zynqmp.img boot_plo.img 0xfffc0000
#    output: plo-aarch64a53-zynqmp.img - contains boot header at the beginning
#

set -e

PATH_IMG=$1
PATH_OUTPUT=$2
ADDR_ENTRY=$3

if [ "$1" == "-h" ] || [ $# -lt 3 ]; then
    echo "usage: $0 <input img file> <output file> <entry address>"
    exit 1
fi


SIZE_IMG=$((($(wc -c < "$PATH_IMG") + 0x3) & ~0x3))

OFFS_DEVH=0x000008c0  # Device image header table offset
OFFS_IMGH=0x00000900  # Image header offset
OFFS_PARTH=0x00000c80 # Partition header offset
OFFS_IMG=0x00001000   # Bootloader or app image offset in the final image
# Image attributes:
# bits[7:6] == 0x0 -> PUF helper data is in eFuse
# bits[9:8] == 0x0 -> No integrity check
# bits[11:10] == 0x2 -> Run on single A53 CPU in 64-bit mode
# bits[15:14] == 0x0 -> RSA authentication decided by eFuse bits
IMG_ATTRS=0x00000800
PUF_SHUT=0x01000020 # 32-bit PUF_SHUT register value
# Partition attributes:
# bit[0] == 0x1 -> TrustZone Secure
# bits[2:1] == 3 -> Start in EL3
# bit[3] == 0 -> Start in AArch64
# bits[4:6] == 1 -> Destination PS
# bit[7] == 0 -> Not encrypted
# bits[8:11] == 1 -> A53 core 0
# bit[18] == 0 -> little-endian
# bit[23] doesn't matter in AArch64
PART_ATTRS=0x00000117


#
# Headers descriptions
#

BOOT_HEADER=(
    0xaa995566    # Width detection word
    0x584c4e58    # Header signature - 'XLNX'
    0x00000000    # Key source
    "$ADDR_ENTRY" # Bootloader entry address in OCM
    "$OFFS_IMG"   # Bootloader offset in the image
    0x00000000    # PMU firmware original image length (0 means no PMU image)
    0x00000000    # Total PMU image length
    "$SIZE_IMG"   # Bootloader size
    "$SIZE_IMG"   # Bootloader size after encryption
    "$IMG_ATTRS"  # Bootloader image attributes
)

DEV_TABLE=(
    0x01020000          # Version
    0x00000001          # Count of image headers
    $((OFFS_PARTH / 4)) # Address to the first partition header offset (words)
    $((OFFS_IMGH / 4))  # Address to the image header
    0x00000000			# Header authentication certificate (unused)
    0x00000000			# Secondary boot device (0 = same as boot device)
    0x00000000          # Reserved (9 words)
    0x00000000
    0x00000000
    0x00000000
    0x00000000
    0x00000000
    0x00000000
    0x00000000
    0x00000000
)

IMG_HEADER=(
    0x0                 # Next image header, 0 if last
    $((OFFS_PARTH / 4)) # First partition header offset (words)
    0x00000000          # Reserved
    0x00000001          # Partition count length
    0x706c6f00          # Image name - "plo\0"
    0x00000000          # String terminator
)

PARTITION_HEADER=(
    $((SIZE_IMG / 4))  # Encrypted partition length (words)
    $((SIZE_IMG / 4))  # Unencrypted partition length (words)
    $((SIZE_IMG / 4))  # Total partition length (words)
    0x00000000         # Next partition header offset (words)
    "$ADDR_ENTRY"      # Entry point of the partition (low 32 bits)
    0x00000000         # Entry point of the partition (high 32 bits)
    0xfffc0000         # Load address of the partition (low 32 bits)
    0x00000000         # Load address of the partition (high 32 bits)
    $((OFFS_IMG / 4))  # Data offset in the image (words)
    "$PART_ATTRS"      # Attribute bits
    0x00000001         # Section count
    0x00000000         # Location of the checksum word
    $((OFFS_IMGH / 4)) # Image header offset (words)
    0x00000000         # Authentication certification word offset
    0x00000000         # Partition number/ID
)


#
# Auxiliary functions
#


reverse() {
    for data in "$@"; do
        for (( i=0; i<4; ++i )); do
            printf "%02x" $((data & 0xff))
            data=$((data >> 8))
        done
    done
}


repeat() {
    for ((i=0; i<$2; ++i)); do
        printf "%s" "$1"
    done
}


checksum() {
    local checksum=0

    for data in "$@"; do
        checksum=$((checksum + data))
    done

    checksum=$((checksum ^ 0xffffffff))
    reverse $checksum
}


#
# Make Boot Image Layout and add it at the beginning of the image
#

make_boot_layout() {
    local filename="boot_layout"
    local z8="00000000"
    local f8="ffffffff"

    # Save layout to the hex file. Empty spaces between headers should be filled with 0xff.
    {
        # Boot Header
        repeat "$(reverse 0x14000000)" 8 # Dummy ARM Vector Table for A53 CPU in 64-bit mode
        reverse "${BOOT_HEADER[@]}"
        checksum "${BOOT_HEADER[@]}"
        repeat "$z8" 8                   # Obfuscated key or Black key - unused
        reverse "$PUF_SHUT"
        repeat "$z8" 10                  # User defined fields
        reverse "$OFFS_DEVH"
        reverse "$OFFS_PARTH"
        repeat "$z8" 6                   # Encryption IVs - unused

        # Register Initialization Table
        repeat "$f8$z8" 256

        # PUF helper data goes here if IMG_ATTRS[7:6] == 0x3

        repeat "$f8" $(((OFFS_DEVH - 0x8b8) / 4 ))

        # Device Image Header Table
        reverse "${DEV_TABLE[@]}"
        checksum "${DEV_TABLE[@]}"
        repeat "$f8" $(((OFFS_IMGH - (OFFS_DEVH + (${#DEV_TABLE[@]} + 1) * 4 )) / 4))

        # Image Header
        reverse "${IMG_HEADER[@]}"
        repeat "$f8" $(((OFFS_PARTH - (OFFS_IMGH + ${#IMG_HEADER[@]} * 4)) / 4))

        # Partition Header
        reverse "${PARTITION_HEADER[@]}"
        checksum "${PARTITION_HEADER[@]}"
        repeat "$f8" $(((OFFS_IMG - (OFFS_PARTH + (${#PARTITION_HEADER[@]} + 1) * 4)) / 4))
    } > "${filename}.hex"

    xxd -r -p "${filename}.hex" > "${filename}.bin"

    # Add boot image layout to the corresponding image
    cat "$PATH_IMG" >> "${filename}.bin"
    mv "${filename}.bin" "$PATH_OUTPUT"

    rm -f "${filename}.hex"
}

make_boot_layout
