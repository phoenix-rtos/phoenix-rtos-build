#!/usr/bin/env bash

# mandatory arguments to run the tests:
# $1 - target arch (i386, arm, riscv64, sparc)
# $2 - toolchain root directory

set -e

PS_PROJECT="$(realpath "$(dirname "${BASH_SOURCE[0]}")/../../..")"

if [ "$#" -lt 2 ]; then
	echo "Usage: $0 <arch> <root> [extra args...]"
	exit 1
fi

case "$1" in
	"i386")
		TARGET=ia32-generic-qemu
		NAME=i386-pc-phoenix
		;;
	"arm"|"riscv64"|"sparc")
		echo "$1 not supported"
		exit 1
		;;
	*)
		echo "Wrong target arch: $1"
		exit 1
		;;
esac

if [ -z "$(ls -A "${PS_PROJECT}/_boot/$TARGET")" ]; then
	echo "You need to built target first"
	exit 1
fi

VER=$("${NAME}-gcc" --version 2> /dev/null | grep -Eo "\b[0-9]+\.[0-9]+\.[0-9]+")
if [ -z "$VER" ]; then
	echo "toolchain ${NAME}-gcc not found"
	exit 1
fi

MAJOR=$(echo "$VER" | cut -d. -f1)
MINOR=$(echo "$VER" | cut -d. -f2)

if [ "$MAJOR" -lt 14 ] || { [ "$MAJOR" -eq 14 ] && [ "$MINOR" -lt 2 ]; }; then
	echo "toolchain version older than 14.2.0"
	exit 1
fi

ROOT_DIR="$2"
BUILD_DIR="${ROOT_DIR}/gcc-${VER}/build"
INIT_FILE="${BUILD_DIR}/${NAME}/libstdc++-v3/testsuite/site.exp"
INIT_TEMP=$(mktemp); trap 'rm -f "$INIT_TEMP"' EXIT

CXXFLAGS="$(TARGET=$TARGET make -f ${PS_PROJECT}/phoenix-rtos-build/Makefile.common export-cxxflags)"

PREFIX_BUILD="${PS_PROJECT}/_build/$TARGET"
CXXFLAGS+=" --sysroot="${PREFIX_BUILD}/sysroot/" -B${PREFIX_BUILD}/sysroot/lib/"

# Currently, only the ia32 platform is supported, so we can increase the stack size to 1 MB.
# Some tests require a large stack. If support for other platforms is added in the future,
# this setting will need to be reviewed and possibly adjusted. Otherwise, some tests may be skipped.
CXXFLAGS+=" -Wl,-z,stack-size=1048576 -Wl,-z,noexecstack"

# We need the path to the directory containing the QEMU expect scripts in the global config.
# However, this file might not exist yet, if so it will be generated later during the make process.
# Therefore, we pass this script knowing that by the time it runs, site.exp (default config) will already exist,
# and we can create a temporary file that adds the 'lappend boards_dir' line with the required path.
SCRIPT="<(cp $INIT_FILE $INIT_TEMP; \
          echo lappend boards_dir ${PS_PROJECT}/phoenix-rtos-build/toolchain/libstdc++_tests >> $INIT_TEMP; \
          cat $INIT_TEMP)"

# run libstdc++ tests
cd "$BUILD_DIR"; make -s CXXFLAGS_FOR_TARGET="$CXXFLAGS" \
                         RUNTESTFLAGS="--target_board=${TARGET} --global_init=${SCRIPT} PS_PROJECT=${PS_PROJECT} ${*:3}" \
                         check-target-libstdc++-v3
