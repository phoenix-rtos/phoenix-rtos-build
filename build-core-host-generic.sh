#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2021 Phoenix Systems
# Author: Tomasz Korniluk
#

# fail immediately if any of the commands fails
set -e

make -C "phoenix-rtos-kernel" install-headers

b_log "Building libphoenix"
make -C "libphoenix" -f Makefile.host all

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" libtinyaes

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all
