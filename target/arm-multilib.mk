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

# Choose if target has MMU based on fPIC flag from multilib.
ifeq ($(subst fPIC,,$(CFLAGS)), $(CFLAGS))
HAVE_MMU := y
else
HAVE_MMU := n
endif
