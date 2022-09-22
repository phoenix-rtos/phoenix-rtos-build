#
# Makefile for libphoenix
#
# IA32 options
#
# Copyright 2018 Phoenix Systems
#

CROSS ?= i386-pc-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2
CFLAGS += $(OLVL)
CFLAGS += -g -Wall -Wstrict-prototypes\
	-m32 -march=i586 -mtune=generic -mno-mmx -mno-sse -fno-pic -fno-pie\
	-fomit-frame-pointer -fno-builtin-malloc\
	-fdata-sections -ffunction-sections

CXXFLAGS += $(filter-out -Wstrict-prototypes, $(CFLAGS))

AR = $(CROSS)ar
ARFLAGS = -r

LD = $(CROSS)ld
LDFLAGS := --gc-sections
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

VADDR_KERNEL_BASE=0xc0000000
VADDR_KERNEL_INIT=$(shell printf "0x%x" $$(($(VADDR_KERNEL_BASE) + 0x110000)))
