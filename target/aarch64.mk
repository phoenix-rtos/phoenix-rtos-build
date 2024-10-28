#
# Makefile for Phoenix-RTOS 3
#
# AArch64 Cortex-A53 options
#
# Copyright 2024 Phoenix Systems
#

CROSS ?= aarch64-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2

cpu := cortex-$(subst aarch64,,$(TARGET_FAMILY))

CFLAGS += -mcpu=$(cpu) -mtune=$(cpu) -fomit-frame-pointer -mstrict-align
CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

LDFLAGS := -Wl,-z,max-page-size=0x1000

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
STRIP := $(CROSS)strip

VADDR_KERNEL_INIT := 0xffffffffc0000000 # Top 1 GB of address space

HAVE_MMU := y
