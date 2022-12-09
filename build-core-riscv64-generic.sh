#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2019 Phoenix Systems
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk, Lukasz Kosinski
#

# fail immediately if any of the commands fails
set -e

b_log "Building phoenix-rtos-kernel"

KERNEL_MAKECMDGOALS="install-headers"

make -C "phoenix-rtos-kernel" $KERNEL_MAKECMDGOALS all

b_log "Building libphoenix"
make -C "libphoenix" all install

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all install

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all install

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all install

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all install

b_log "Building hostutils"
make -C "phoenix-rtos-hostutils" -f Makefile.old all
cp "$PREFIX_BUILD_HOST/prog.stripped/syspagen" "$PREFIX_BOOT"

#FIXME: tests should not always be built as a part of CORE
b_log "Building phoenix-rtos-tests"
make -C "phoenix-rtos-tests" all
