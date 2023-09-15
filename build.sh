#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR/..
#
# Shell script for building Phoenix-RTOS based firmware
#
# Main builder
#
# Copyright 2018, 2019 Phoenix Systems
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk
#

set -e
ORIG_ENV="$(env)"

# Colon-separated list of dirs to overlay the default rootFS.
# It can be overwritten by build.project scripts.
ROOTFS_OVERLAYS=""

source ./phoenix-rtos-build/build.subr
source ./build.project

PREFIX_PROJECT="$(pwd)"

# Some makefiles add "$PROJECT_PATH/" to their include path so it has to be set
if [ -z "$PROJECT_PATH" ]; then
    echo "PROJECT_PATH is not set (or is empty)"
    exit 1;
fi

_TARGET_FOR_HOST_BUILD="host-generic-pc"

PREFIX_BUILD="$PREFIX_PROJECT/_build/$TARGET"
PREFIX_BUILD_HOST="$PREFIX_PROJECT/_build/$_TARGET_FOR_HOST_BUILD"
PREFIX_FS="$PREFIX_PROJECT/_fs/$TARGET"
PREFIX_BOOT="$PREFIX_PROJECT/_boot/$TARGET"

PREFIX_PROG="$PREFIX_BUILD/prog/"
PREFIX_PROG_STRIPPED="$PREFIX_BUILD/prog.stripped/"

PREFIX_A="$PREFIX_BUILD/lib/"
PREFIX_H="$PREFIX_BUILD/include/"
PREFIX_SYSROOT=""  # empty by default (use toolchain sysroot)

PLO_SCRIPT_DIR="$PREFIX_BUILD/plo-scripts"

PREFIX_ROOTFS="$PREFIX_FS/root/"
: "${PREFIX_ROOTSKEL:="$PREFIX_PROJECT/_fs/root-skel/"}"


# LIBPHOENIX_DEVEL_MODE:
#  - if enabled (y): use project-specific sysroot (PREFIX_SYSROOT) and install kernel headers + compile/install libphoenix
#  - if disabled (n or not set): use toolchain sysroot, don't install kernel headers, don't compile libphoenix
#TODO: change default value to 'n' when the toolchain-supplied sysroot will be stable enough
: "${LIBPHOENIX_DEVEL_MODE:=y}"

if [ "$LIBPHOENIX_DEVEL_MODE" = "y" ]; then
	PREFIX_SYSROOT="$PREFIX_BUILD/sysroot"
fi

# Default project's overlay directory, it does not have to exist.
ROOTFS_OVERLAYS="$PROJECT_PATH/rootfs-overlay:${ROOTFS_OVERLAYS}"

CC=${CROSS}gcc
AS=${CROSS}as
LD=${CROSS}ld
AR=${CROSS}ar

MAKEFLAGS="--no-print-directory -j 9"

export TARGET TARGET_FAMILY TARGET_SUBFAMILY TARGET_PROJECT PROJECT_PATH PREFIX_PROJECT PREFIX_BUILD\
	PREFIX_BUILD_HOST PREFIX_FS PREFIX_BOOT PREFIX_PROG PREFIX_PROG_STRIPPED PREFIX_A\
	PREFIX_H PREFIX_ROOTFS CROSS CFLAGS CXXFLAGS LDFLAGS CC LD AR AS MAKEFLAGS DEVICE_FLAGS PLO_SCRIPT_DIR\
	PREFIX_SYSROOT LIBPHOENIX_DEVEL_MODE

# export flags for ports - call make only after all necessary env variables are already set
EXPORT_CFLAGS="$(make -f phoenix-rtos-build/Makefile.common export-cflags)"
# Convert ldflags to format recognizable by gcc, for example -q -> -Wl,-q
EXPORT_LDFLAGS="$(make -f phoenix-rtos-build/Makefile.common export-ldflags)"

export EXPORT_CFLAGS EXPORT_LDFLAGS


#
# Parse command line
#
if [ $# -lt 1 ]; then
	echo "Build options should be specified!"
	echo "Usage: build.sh [clean] [all] [host] [fs] [core] [test] [ports] [project] [image]";
	exit 1;
fi

B_CLEAN="n"
B_FS="n"
B_CORE="n"
B_HOST="n"
B_PORTS="n"
B_PROJECT="n"
B_IMAGE="n"
B_TEST="n"

# GA CI passes all params as quoted first param - split on ' ' if necessary
ARGS=("$@")
[ "$#" -eq 1 ] && read -ra ARGS <<< "$1"

for arg in "${ARGS[@]}"; do
	case "$arg"
	in
		clean)
			B_CLEAN="y";;
		fs)
			B_FS="y";;
		core)
			B_CORE="y";;
		host)
			B_HOST="y";;
		test|tests)
			B_TEST="y";;
		ports)
			B_PORTS="y";;
		project)
			B_PROJECT="y";;
		image)
			B_IMAGE="y";;
		all)
			B_FS="y"; B_CORE="y"; B_HOST="y"; B_PORTS="y"; B_PROJECT="y"; B_IMAGE="y";;
		*)
			echo "Unknown build option: \"$arg\"."
			exit 1;;
	esac;
done

#
# Clean if requested
#
if [ "$B_CLEAN" = "y" ]; then
	b_log "Cleaning build dirs"
	rm -rf "$PREFIX_BUILD" "$PREFIX_BUILD_HOST"
	rm -rf "$PREFIX_FS"
	rm -rf "$PREFIX_BOOT"
fi

#
# Prepare
#
mkdir -p "$PREFIX_BUILD"
mkdir -p "$PREFIX_BUILD_HOST"
mkdir -p "$PREFIX_BOOT"
mkdir -p "$PREFIX_PROG" "$PREFIX_PROG_STRIPPED"

if [ -n "$PREFIX_SYSROOT" ]; then
	mkdir -p "$PREFIX_SYSROOT" "$PREFIX_SYSROOT/include" "$PREFIX_SYSROOT/usr"

	# libc includes needs to be accessible by ${SYSROOT}/usr/local/include for C++ headers to work
	(cd "$PREFIX_SYSROOT/usr" && ln -sfn . local)
	# see sysroot-setup.mk for next steps in sysroot setup
fi

if declare -f "b_prepare" > /dev/null; then
	b_prepare
fi

if command -v git > /dev/null && [ -a ".git" ]; then
	echo " $(git rev-parse HEAD) $(basename "$(git rev-parse --show-toplevel)") ($(git describe --always --dirty))" > "${PREFIX_BUILD}/git-version"
	git submodule status --recursive >> "${PREFIX_BUILD}/git-version"
else
	echo "not available" > "${PREFIX_BUILD}/git-version"
fi

#
# Preparing filesystem
#
if [ "${B_FS}" = "y" ] && [ -d  "${PREFIX_ROOTSKEL}" ]; then
	b_log "Preparing filesystem"

	mkdir -p "${PREFIX_ROOTFS}"
	cp -a "${PREFIX_ROOTSKEL}/." "${PREFIX_ROOTFS}"
	mkdir -p "$PREFIX_ROOTFS/"{dev,etc,local,data,mnt,tmp,var,usr}

	# ROOTFS_OVERLAYS contains colon-separated path
	(
		IFS=:
		for path in $ROOTFS_OVERLAYS; do
			if [ -d "$path" ]; then
				echo "Applying overlay: $path"
				cp -a "${path}/." "${PREFIX_ROOTFS}"
			else
				echo "Not existing rootfs overlay: $path"
			fi
		done
	)

	b_log "Saving git-version"
	install -m 664 "${PREFIX_BUILD}/git-version" "$PREFIX_FS/root/etc"
fi

#
# Build host tools
#
if [ "${B_HOST}" = "y" ]; then
	if [ "$TARGET" != "$_TARGET_FOR_HOST_BUILD" ]; then
		# if not already building for host - re-exec with clean env
		(env "$ORIG_ENV" TARGET=$_TARGET_FOR_HOST_BUILD ./phoenix-rtos-build/build.sh host)
	else
		source ./phoenix-rtos-build/build-host-tools.sh
	fi
fi

# always install hostutils if they are present
b_log "Installing hostutils"
HOSTUTILS=(metaelf phoenixd psdisk psu syspagen)
for tool in "${HOSTUTILS[@]}"; do
	toolfile="$PREFIX_BUILD_HOST/prog.stripped/$tool"
	[ -e "$toolfile" ] && cp -a "$toolfile" "$PREFIX_BOOT"
done

#
# Build core part
#
if [ "${B_CORE}" = "y" ]; then
	"./phoenix-rtos-build/build-core-${TARGET_FAMILY}-${TARGET_SUBFAMILY}.sh"
fi

#
# Build test part
#
if [ "${B_TEST}" = "y" ]; then
	b_build_test
fi

#
# Build ports
#
if [ "${B_PORTS}" = "y" ] && [ -d phoenix-rtos-ports ]; then
	./phoenix-rtos-ports/build.sh
fi

#
# Build project part
#
if [ "${B_PROJECT}" = "y" ]; then
	b_build
fi

#
# Build final filesystems
#
if [ "${B_IMAGE}" = "y" ]; then
	b_image
fi
