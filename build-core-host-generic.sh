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

b_log "Building libphoenix"
make -C "libphoenix" -f Makefile.host all

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all

b_log "Building hostutils"
make -C "phoenix-rtos-hostutils" -f Makefile.old $CLEAN all
cp "$PREFIX_BUILD_HOST/prog.stripped/phoenixd" "$PREFIX_BOOT"
cp "$PREFIX_BUILD_HOST/prog.stripped/psdisk" "$PREFIX_BOOT"
cp "$PREFIX_BUILD_HOST/prog.stripped/psu" "$PREFIX_BOOT"
