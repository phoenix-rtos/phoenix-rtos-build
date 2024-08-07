#
# Makefile for Phoenix-RTOS 3
#
# ARM (Cortex-A5/A7/A9) options
#
# Copyright 2018 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2

cpu := cortex-$(subst armv7,,$(TARGET_FAMILY))

ifeq ($(TARGET_SUBFAMILY), imx6ull)
  CFLAGS += -mfpu=neon-vfpv4 -mfloat-abi=hard
else ifeq ($(TARGET_SUBFAMILY), zynq7000)
  CFLAGS += -mfpu=neon-vfpv3 -mfloat-abi=hard
else
	$(error Incorrect TARGET.)
endif

CFLAGS += -mcpu=$(cpu) -mtune=$(cpu) -mthumb -fomit-frame-pointer -mno-unaligned-access
CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

LDFLAGS := -Wl,-z,max-page-size=0x1000

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
STRIP := $(CROSS)strip

VADDR_KERNEL_INIT := 0xc0000000

HAVE_MMU := y
