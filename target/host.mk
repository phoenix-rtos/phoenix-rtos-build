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
