#!/usr/bin/env bash
# $1 - toolchain target (e.g. arm-phoenix)
# $2 - toolchain install absolute path (i.e. no "." or ".." in the path)

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

log() {
    echo -e "\e[35;1m$*\e[0m"
}

# targets for libphoenix and phoenix-rtos-kernel for installing headers
declare -A TOOLCHAN_TO_PHOENIX_TARGETS=(
    [arm-phoenix]="armv7a9-zynq7000 armv7a7-imx6ull armv7m7-imxrt106x armv7m4-stm32l4x6"
    [i386-pc-phoenix]="ia32-generic"
    [riscv64-phoenix]="riscv64-generic"
    [sparc-phoenix]="sparcv8leon3-gr716 sparcv8leon3-gr712rc"
)

TARGET="$1"
BUILD_ROOT="$2"
BUILD_DIR="${BUILD_ROOT}/_build"

if [ -z "$TARGET" ] || [ -z "${TOOLCHAN_TO_PHOENIX_TARGETS[$TARGET]}" ]; then
    echo "Missing or invalid target provided! Abort."
    echo "officially supported targets:"
    printf "%s\n" "${!TOOLCHAN_TO_PHOENIX_TARGETS[@]}"
    exit 1
fi

PHOENIX_TARGETS="${TOOLCHAN_TO_PHOENIX_TARGETS[$TARGET]}"

if [ -z "$BUILD_ROOT" ]; then
    echo "No toolchain install path provided! Abort."
    exit 1
fi

if [ "${BUILD_ROOT:0:1}" != "/" ]; then
    echo "Path must not be relative."
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/../../phoenix-rtos-kernel/Makefile" ] || [ ! -f "$SCRIPT_DIR/../../libphoenix/Makefile" ]; then
    echo "phoenix-rtos-kernel or libphoenix missing! Please use full phoenix-rtos-project repo for toolchain building. Abort."
    exit 1
fi

# Those env variables override command line options passed to configure scripts
# This check was added due to libstdc++ configure using host compiler instead of cross compiler
# TODO: check if all stages are affected. If not then consider using unset in those stages
if [[ -v CC || -v CFLAGS || -v LIBS || -v CPPFLAGS || -v CXX || -v CXXFLAGS || -v CPP || -v CXXCPP || -v CXXFILT ]]; then
    echo "Environment contains variables that should not be set. Abort."
    echo "Make sure to unset CC CFLAGS LIBS CPPFLAGS CXX CXXFLAGS CPP CXXCPP CXXFILT"
    exit 1
fi

if command -v "${TARGET}-gcc" > /dev/null; then
    echo "Command \"${TARGET}-gcc\" found in PATH. Abort."
    echo "Make sure to to remove existing toolchain from PATH"
    exit 1
fi

# old legacy versions of the compiler:
#BINUTILS=binutils-2.28
#GCC=gcc-7.1.0

BINUTILS=binutils-2.34
GCC=gcc-9.5.0

TOOLCHAIN_PREFIX="${BUILD_ROOT}/${TARGET}"
SYSROOT="${TOOLCHAIN_PREFIX}/${TARGET}"
MAKEFLAGS="-j9 -s"
export MAKEFLAGS

mkdir -p "${TOOLCHAIN_PREFIX}"
mkdir -p "${BUILD_DIR}"
cp ./*.patch "${BUILD_DIR}"
cd "${BUILD_DIR}"

download() {
    log "downloading packages"

    [ ! -f ${BINUTILS}.tar.bz2 ] && wget "http://ftp.gnu.org/gnu/binutils/${BINUTILS}.tar.bz2"
    [ ! -f ${GCC}.tar.xz ] && wget "http://www.mirrorservice.org/sites/ftp.gnu.org/gnu/gcc/${GCC}/${GCC}.tar.xz"

    log "extracting packages"
    [ ! -d ${BINUTILS} ] && tar jxf ${BINUTILS}.tar.bz2
    [ ! -d ${GCC} ] && tar Jxf ${GCC}.tar.xz

    log "downloading GCC dependencies"
    (cd "$GCC" && ./contrib/download_prerequisites)
}

build_binutils() {
    log "patching ${BINUTILS}"
    for patchfile in "${BINUTILS}"-*.patch; do
        if [ ! -f "${BINUTILS}/$patchfile.applied" ]; then
            patch -d "${BINUTILS}" -p1 < "$patchfile"
            touch "${BINUTILS}/$patchfile.applied"
        fi
    done

    log "building binutils"
    rm -rf "${BINUTILS}/build"
    mkdir -p "${BINUTILS}/build"
    pushd "${BINUTILS}/build" > /dev/null

    ../configure --target="${TARGET}" --prefix="${TOOLCHAIN_PREFIX}" \
                 --with-sysroot="${SYSROOT}" --enable-lto --enable-deterministic-archives
    make

    log "installing binutils"
    make install
    popd > /dev/null
}

build_gcc_stage1() {
    log "patching ${GCC}"
    for patchfile in "${GCC}"-*.patch; do
        if [ ! -f "${GCC}/$patchfile.applied" ]; then
            patch -d "${GCC}" -p1 < "$patchfile"
            touch "${GCC}/$patchfile.applied"
        fi
    done

    log "building GCC (stage1)"
    rm -rf "${GCC}/build"
    mkdir -p "${GCC}/build"
    pushd "${GCC}/build" > /dev/null

    # GCC compilation options
    # --with-sysroot -> cross-compiler sysroot
    # --with-gxx-include-dir -> configure as a subdir of sysroot for c++ includes to work with external (out-of-toolchain) sysroot
    # --with-newlib -> do note generate standard library includes by fixincludes, do not include _eprintf in libgcc
    # --disable-libssp -> stack smashing protector library disabled
    # --disable-nls -> all compiler messages will be in english
    # --enable-tls -> enable Thread Local Storage
    # --enable-initfini-array -> force init/fini array support instead of .init .fini sections
    # --disable-decimal-float -> not relevant for other than i386 and PowerPC
    # --disable-libquadmath -> not using fortran and quad floats
    # --enable-threads=posix -> enable POSIX threads


    # stage1 compiler (gcc only)
    ../configure --target="${TARGET}" --prefix="${TOOLCHAIN_PREFIX}" \
                 --with-sysroot="${SYSROOT}" \
                 --with-gxx-include-dir="${SYSROOT}/include/c++" \
                 --enable-languages=c,c++ --with-newlib \
                 --with-headers=yes \
                 --enable-tls \
                 --enable-initfini-array \
                 --disable-decimal-float \
                 --disable-libquadmath \
                 --disable-libssp --disable-nls \
                 --enable-threads=posix

    make all-gcc

    log "installing GCC (stage1)"
    make install-gcc
    popd > /dev/null
}

build_libc() {
    # use new compiler for the below builds
    OLDPATH="$PATH"
    PATH="$TOOLCHAIN_PREFIX/bin":$PATH
    export PATH

    # standard library headers should be installed in $SYSROOT/usr/include
    # for fixincludes to work the headers need to be in $SYSROOT/usr/include, for libgcc compilation in $SYSROOT/include
    # create symlink for this stage (arm-none-eabi-gcc does the same - see https://github.com/xpack-dev-tools/arm-gcc-original-scripts/blob/master/build-toolchain.sh)
    mkdir -p "${SYSROOT}/usr/include"
    ln -snf usr/include "${SYSROOT}/include"

    for phx_target in $PHOENIX_TARGETS; do
        log "[$phx_target] installing kernel headers"
        make -C "$SCRIPT_DIR/../../phoenix-rtos-kernel" TARGET="$phx_target" install-headers

        # FIXME: libphoenix should be installed for all supported multilib target variants
        log "[$phx_target] installing libphoenix"
        make -C "$SCRIPT_DIR/../../libphoenix" TARGET="$phx_target" clean install
    done

    PATH="$OLDPATH"
}

build_gcc_stage2() {
    pushd "$BUILD_DIR/${GCC}/build" > /dev/null

    # (hackish) instead of reconfiguring and rebuilding whole gcc
    # just force rebuilding internal includes (and fixincludes)
    # remove stamp file for internal headers generation
    rm gcc/stmp-int-hdrs

    log "building GCC (stage2)"
    make all-gcc all-target-libgcc

    log "installing GCC (stage2)"
    make install-gcc install-target-libgcc

    # remove `include` symlink to install c++ headers in $SYSROOT/include/c++ as expected
    rm -rf "${SYSROOT:?}/include"
    popd > /dev/null
}

build_libstdcpp() {
    # use new compiler for the below builds
    OLDPATH="$PATH"
    PATH="$TOOLCHAIN_PREFIX/bin":$PATH

    # set flags for arm to guarantee PIC for libstdc++
    WITHPIC=
    if [[ "$TARGET" = "arm-phoenix" || "$TARGET" = "sparc-phoenix" ]]; then
        WITHPIC="--with-pic"
    fi

    # create "libbuilddir" directory for libstdc++
    rm -rf "${BUILD_DIR}/${GCC}/build/${TARGET}/libstdc++-v3"
    mkdir -p "${BUILD_DIR}/${GCC}/build/${TARGET}/libstdc++-v3"
    pushd "${BUILD_DIR}/${GCC}/build/${TARGET}/libstdc++-v3" > /dev/null

    log "building stdlibc++"
    # LIBSTDC++ compilation options
    # --host -> target is a host for libstdc++
    # --with-gxx-include-dir -> configure as a subdir of sysroot for c++ includes to work with external (out-of-toolchain) sysroot
    # --with-libphoenix -> use libphoenix as standard C library
    # --enable-tls -> enable Thread Local Storage
    # --disable-nls ->  all compiler messages will be in english
    # --disable-shared -> disable building shared libraries [default=yes]
    # --srcdir -> point to the directory with source files, because the current directory is incorrect for srcdir
    # --with-pic -> build library files as PIC files

    # now, we use files from generic for every category in libstdc++v3/config directory
    ../../../libstdc++-v3/configure --target="${TARGET}" \
                                    --host="${TARGET}" \
                                    --prefix="${SYSROOT}" \
                                    --with-gxx-include-dir="${SYSROOT}/include/c++" \
                                    --with-libphoenix \
                                    --enable-tls \
                                    --disable-nls \
                                    --disable-shared \
                                    --srcdir="../../../libstdc++-v3" \
                                    $WITHPIC

    make

    log "installing stdlibc++"
    make install

    popd > /dev/null
    PATH="$OLDPATH"
}

strip_binaries() {
    log "stripping binaries"
    if [ "$(uname)" = "Darwin" ]; then
        find "$TOOLCHAIN_PREFIX" -type f -perm +111 -exec strip {} + || true
    else
        find "$TOOLCHAIN_PREFIX" -type f -perm /111 -exec strip {} + || true
    fi

    # NOTE: we could also strip target libraries, but let's leave debug sections for ease of development
}


### MAIN ###

# comment out some parts if You need "incremental build" for testing

download;
build_binutils;
build_gcc_stage1;

build_libc;
build_gcc_stage2;
build_libstdcpp;

strip_binaries;

echo "Toolchain for target family '$TARGET' has been installed in '$TOOLCHAIN_PREFIX'"
echo "Please add it to PATH:"
echo "PATH=$TOOLCHAIN_PREFIX/bin:\$PATH"
