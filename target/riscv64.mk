#
# Makefile for Phoenix-RTOS 3
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

# Don't check when building toolchain - FIXME: libphoenix in toolchain should be built as multilib
ifneq ($(NOCHECKENV),1)
  ifeq ($(RISCV_ISA_STRING),)
    $(error RISCV_ISA_STRING is not set. TARGET=$(TARGET))
  endif
  CFLAGS += -march=$(RISCV_ISA_STRING)
endif

CFLAGS += -fomit-frame-pointer -mcmodel=medany

CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

LDFLAGS :=

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

STRIP := $(CROSS)strip

VADDR_KERNEL_INIT := 0x0000003fc0000000

HAVE_MMU := y
