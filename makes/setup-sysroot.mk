# setting up toolchain sysroot
# WARN: these compiler options were carefully crafted, think twice before changing them!
#
# C++ includes and include-fixed are problematic as they are using #include_next
# we need to copy them into our sysroot in special paths to ensure they will be searched in order:
# c++ -> include-fixed -> libc include -> other toolchain paths
#
# gcc options helpful in development:  -H (include tree) -v (include paths to be searched)
# echo "#warning toolchain include" >> $($CC -print-sysroot)/usr/include/stdint.h

# use stamp file to setup sysroot only once regardless of the component being built
_SYSROOT_STAMPFILE := $(PREFIX_BUILD)/.stamp_sysroot


ifneq ($(PREFIX_SYSROOT),)
  # basic sysroot define, compile-time hardcoded toolchain paths would still be searched (see gcc/cppdefaults.c)
  SYSROOT_OPTS := --sysroot="$(PREFIX_SYSROOT)/"

  # shouldn't be necessary but without it - we're linking against toolchain crt0.o
  SYSROOT_OPTS += -B$(PREFIX_SYSROOT)/lib/

  # magically rearranges toolchain paths that sysroot libc subdir would be searched first :)
  SYSROOT_OPTS += -iprefix "$(PREFIX_SYSROOT)/"

  CFLAGS += $(SYSROOT_OPTS)
  CXXFLAGS += $(SYSROOT_OPTS)

# WARN: assuming there are no multilib c++ headers
$(_SYSROOT_STAMPFILE):
	@mkdir -p $(PREFIX_SYSROOT)/include
	$(SIL)cp -a "$$($(CC) -print-sysroot)/include/c++" "$(PREFIX_SYSROOT)/include/"
	$(SIL)cp -a $(shell $(CC) -E -Wp,-v -x c /dev/null 2>&1 | awk '!/ignoring/ && /include-fixed/ {print $0}') "$(PREFIX_SYSROOT)"
	@touch $@

else
$(_SYSROOT_STAMPFILE):
	@mkdir -p $(PREFIX_BUILD)
	@touch $@
endif

prepare_sysroot: $(_SYSROOT_STAMPFILE)

# make it an order rule for any build/install target
all: | prepare_sysroot
install: | prepare_sysroot
install-%: | prepare_sysroot
