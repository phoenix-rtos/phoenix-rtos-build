#!/bin/bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2018, 2019 Phoenix Systems
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk
#

# fail immediately if any of the commands fails
set -e

b_log "Building phoenix-rtos-kernel"
KERNEL_MAKECMDGOALS="install-headers"
make -C "phoenix-rtos-kernel" $KERNEL_MAKECMDGOALS all

b_log "Building libphoenix"
make -C "libphoenix" all install

b_log "Building unity"
make -C "phoenix-rtos-tests" unity

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all install

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all

# FIXME: compile host tools using host-pc target?
b_log "Building hostutils"
make -C "phoenix-rtos-hostutils" -f Makefile.old $CLEAN all
cp "$PREFIX_BUILD_HOST/prog.stripped/phoenixd" "$PREFIX_BOOT"