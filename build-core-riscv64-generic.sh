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
make -C "phoenix-rtos-kernel" all

if [ "$LIBPHOENIX_DEVEL_MODE" = "y" ]; then
	make -C "phoenix-rtos-kernel" install-headers

	b_log "Building libphoenix"
	make -C "libphoenix" all install
fi

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all install

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all install

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all install

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all install

b_log "Building posixsrv"
make -C "phoenix-rtos-posixsrv" all install


b_log "Building cfs"

mkdir -p "$PREFIX_BUILD/cfs"
cd "$PREFIX_BUILD/cfs" && \
cmake -DOSAL_SYSTEM_BSPTYPE=generic-phoenix -DINSTALL_TARGET_LIST=. -DOSAL_CONFIG_DEBUG_PRINTF=TRUE \
	-DOSAL_CONFIG_INCLUDE_DYNAMIC_LOADER=FALSE -DOSAL_CONFIG_INCLUDE_STATIC_LOADER=FALSE \
	-DCMAKE_TOOLCHAIN_FILE="$PREFIX_PROJECT/cFS/cfe/cmake/sample_defs/toolchain-phoenix.cmake" \
	-DCMAKE_INSTALL_PREFIX="$PREFIX_FS/root" -DENABLE_UNIT_TESTS=true \
	-DCMAKE_BUILD_TYPE=Debug \
	-DOSAL_CONFIG_DEBUG_PERMISSIVE_MODE=TRUE "$PREFIX_PROJECT/cFS/osal" && \
	make && \
	make install

# for f in "$PREFIX_PROG_STRIPPED/cfs/"*; do
# 	if [ -f "$f" ]; then
# 		b_install "$f" /bin/cfs
# 	fi
# done
# b_install "$PREFIX_PROG_STRIPPED/cfs/bin-sem-test" /bin
