#
# Makefile for Phoenix-RTOS 3
#
# ARM Multilib options
#
# Copyright 2025 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

# common CFLAGS
OLVL ?= -O2
CFLAGS += -fomit-frame-pointer -mno-unaligned-access

LDFLAGS := -Wl,-z,max-page-size=0x10

# CFLAGS are passed via the last part of TARGET
MULTI_FLAGS := $(subst $(TARGET_FAMILY)-$(TARGET_SUBFAMILY)-,,$(TARGET))

CFLAGS += $(subst @, -, $(MULTI_FLAGS))

CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

STRIP := $(CROSS)strip

TARGET_PIC_FLAG := -fpic
TARGET_PIE_FLAG := -fpie

# Always build as PIC for coherence.
LIBPHOENIX_PIC ?= y

# Choose if target has MMU based on -mno-pic-data-is-text-relative or -mfdpic flag from multilib.
ifeq ($(subst pic,,$(CFLAGS)), $(CFLAGS))
HAVE_MMU := y
else
HAVE_MMU := n
endif

ifeq ($(subst -mno-pic-data-is-text-relative,,$(CFLAGS)), $(CFLAGS))
HAVE_SHLIB := y
LIBPHOENIX_SHARED ?= y
else
HAVE_SHLIB := n
LIBPHOENIX_SHARED ?= n
endif
