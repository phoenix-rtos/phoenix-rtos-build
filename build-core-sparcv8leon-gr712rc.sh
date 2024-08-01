#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2023 Phoenix Systems
# Author: Lukasz Leczkowski
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

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all install

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all install

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all install

b_log "Building posixsrv"
make -C "phoenix-rtos-posixsrv" all install
