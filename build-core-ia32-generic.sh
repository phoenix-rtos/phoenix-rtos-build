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

if [ "$CORE_NETWORKING_DISABLE" != "y" ]; then
	b_log "Building phoenix-rtos-lwip"
	make -C "phoenix-rtos-lwip" all
	b_install "$PREFIX_PROG_STRIPPED/lwip" /sbin
fi

b_log "Building posixsrv"
make -C "phoenix-rtos-posixsrv" all install

b_log "Building cfs"

# mkdir -p cd cFS/osal/build && \
# cd cFS/osal/build && \
# cmake -DOSAL_SYSTEM_BSPTYPE=generic-phoenix -DINSTALL_TARGET_LIST=. -DOSAL_CONFIG_DEBUG_PRINTF=TRUE \
# 	-DCMAKE_TOOLCHAIN_FILE=../../cfe/cmake/sample_defs/toolchain-phoenix.cmake \
# 	-DCMAKE_INSTALL_PREFIX="$PREFIX_PROG_STRIPPED/cfs" -DENABLE_UNIT_TESTS=true \
# 	-DOSAL_CONFIG_DEBUG_PERMISSIVE_MODE=TRUE .. && \
# 	make && make install && \
# cd ../../..

# for f in "$PREFIX_PROG_STRIPPED/cfs/"*; do
# 	if [ -f "$f" ]; then
# 		b_install "$f" /cfs
# 	fi
# done

# mkdir -p "$PREFIX_BUILD/cfs"
# mkdir -p "$PREFIX_FS/root/cfs"

# b_log "Building cFS (into $PREFIX_BUILD/cfs)"

# set variables for make
# export SIMULATION=phoenix
# export O="$PREFIX_BUILD/cfs"
# export INSTALLPREFIX="/cfs"
# export DESTDIR="$PREFIX_FS/root"

# (un)set build variables to not interfere with cFS build
# (build of host tools must use the host compiler)
env -u CC -u LD -u AS -u AR \
	EXPORT_CC="$CC" EXPORT_LD="$LD" EXPORT_AS="$AS" EXPORT_AR="$AR" \
	make -C cFS prep

# export EXPORT_CC="$CC" EXPORT_LD="$LD" EXPORT_AS="$AS" EXPORT_AR="$AR"

# cd "$PREFIX_BUILD/cfs" && \
# cmake -DOSAL_SYSTEM_BSPTYPE=generic-phoenix -DINSTALL_TARGET_LIST=. -DOSAL_CONFIG_DEBUG_PRINTF=TRUE \
# 	-DOSAL_CONFIG_INCLUDE_DYNAMIC_LOADER=FALSE -DOSAL_CONFIG_INCLUDE_STATIC_LOADER=FALSE \
# 	-DCMAKE_TOOLCHAIN_FILE="$PREFIX_PROJECT/cFS/cfe/cmake/sample_defs/toolchain-phoenix.cmake" \
# 	-DCMAKE_INSTALL_PREFIX="$PREFIX_FS/root/cfs" -DENABLE_UNIT_TESTS=true \
# 	-DCMAKE_BUILD_TYPE=Debug \
# 	-DOSAL_CONFIG_DEBUG_PERMISSIVE_MODE=TRUE "$PREFIX_PROJECT/cFS/osal" && \
# 	make && \
# 	make install

# this can be run from current env,
# info is saved in cmake-generated files
make -C cFS
make -C cFS install

