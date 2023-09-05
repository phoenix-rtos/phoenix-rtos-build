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

CC = $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2
CFLAGS += -fomit-frame-pointer -mcmodel=medany -fno-builtin

CXXFLAGS := $(CFLAGS)

AR = $(CROSS)ar
ARFLAGS = -r

LD = $(CROSS)ld
LDFLAGS :=
GCCLIB := $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)
CRTBEGIN := $(shell $(CC) $(CFLAGS) -print-file-name=crtbegin.o)
CRTEND := $(shell $(CC) $(CFLAGS) -print-file-name=crtend.o)
PHOENIXLIB := $(shell $(CC) $(CFLAGS) -print-file-name=libphoenix.a)
# The filter-out enables proper building because if libstdc++ is not available, LIBSTDCPP will be empty.
LIBSTDCPP := $(filter-out libstdc++.a, $(shell $(CXX) $(CXXFLAGS) -print-file-name=libstdc++.a))
LDLIBS := $(LIBSTDCPP) $(PHOENIXLIB) $(GCCLIB) $(CRTBEGIN) $(CRTEND)

OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

STRIP = $(CROSS)strip

VADDR_KERNEL_INIT = 0x0000003fc0000000
