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
CFLAGS += -m32 -march=i586 -mtune=generic -mno-mmx -mno-sse -fno-pic -fno-pie\
	-fomit-frame-pointer -fno-builtin-malloc

CXXFLAGS := $(CFLAGS)

AR = $(CROSS)ar
ARFLAGS = -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

LDFLAGS :=

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

STRIP := $(CROSS)strip

VADDR_KERNEL_BASE=0xc0000000
VADDR_KERNEL_INIT=$(shell printf "0x%x" $$(($(VADDR_KERNEL_BASE) + 0x110000)))
