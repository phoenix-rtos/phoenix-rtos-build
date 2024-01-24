#
# Makefile for libphoenix
#
# RISCV64 options
#
# Copyright 2018 Phoenix Systems
#
# %LICENSE%
#

CROSS ?= riscv64-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2
CFLAGS += -fomit-frame-pointer -mcmodel=medany

CXXFLAGS := $(CFLAGS)

AR = $(CROSS)ar
ARFLAGS = -r

LD = $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

LDFLAGS :=

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

STRIP := $(CROSS)strip

VADDR_KERNEL_INIT := 0x0000003fc0000000
