#
# Common Makefile for host
#
# Copyright 2018-2021 Phoenix Systems
#
# %LICENSE%
#

CROSS :=

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2
CFLAGS += -fomit-frame-pointer

AR := $(CROSS)ar
ARFLAGS = -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
STRIP := $(CROSS)strip

# Sanitizers
ifneq ($(NOSAN), 1)
  CFLAGS += -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
endif

CXXFLAGS := $(CFLAGS)

# install unstripped binaries in rootfs
# (cruicial for tests binaries with debug info for meaningful sanitizers info)
ROOTFS_INSTALL_UNSTRIPPED := y

# don't use sysroot on host
LIBPHOENIX_DEVEL_MODE := n
PREFIX_SYSROOT :=

# check if linker is an apple linker
LINKER := $(shell $(CC) -Wl,-v 2>&1)
ifeq ($(findstring PROJECT:ld, $(LINKER)), PROJECT:ld)
  LDFLAGS_GC_SECTIONS := $(LDFLAGS_PREFIX)-dead_strip
  LDFLAGS_WHOLE_ARCHIVE_BEGIN := $(LDFLAGS_PREFIX)-all_load
  # (set to empty, so ?= won't assign default value)
  LDFLAGS_WHOLE_ARCHIVE_END := 
endif
