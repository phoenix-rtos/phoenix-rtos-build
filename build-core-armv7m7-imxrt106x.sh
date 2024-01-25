#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2018-2024 Phoenix Systems
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk
#

# fail immediately if any of the commands fails
set -e

b_log "Building phoenix-rtos-kernel"
make -C "phoenix-rtos-kernel" all

if [ "$LIBPHOENIX_DEVEL_MODE" = "y" ]; then
	make -C "phoenix-rtos-kernel" install-headers

	b_log "Building libphoenix"
	make -C "libphoenix" all install
fi

b_log "Building libtty"
make -C "phoenix-rtos-devices" libtty libtty-install

b_log "Building libposixsrv"
make -C "phoenix-rtos-posixsrv" libposixsrv libposixsrv-install

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all install

b_log "Building phoenix-rtos-usb"
make -C "phoenix-rtos-usb" libusb usb-headers install

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all install

b_log "Building phoenix-rtos-usb"
make -C "phoenix-rtos-usb" usb usb-install USB_HCD_LIBS="libusbehci"

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all install

if [ "$CORE_NETWORKING_DISABLE" != "y" ]; then
	b_log "phoenix-rtos-lwip"
	make -C "phoenix-rtos-lwip" all install
fi
