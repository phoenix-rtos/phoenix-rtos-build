#
# Makefile for Phoenix-RTOS 3
#
# ARMv8 (Cortex-M33) options
#
# Copyright 2018, 2020, 2024 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

# common Cortex-M CFLAGS
OLVL ?= -O2
CFLAGS += -mthumb -fomit-frame-pointer -mno-unaligned-access

# TODO hard float perhaps? To be decided
CFLAGS += -mcpu=cortex-m33 -mfloat-abi=soft -fstack-usage

VADDR_KERNEL_INIT := $(KERNEL_PHADDR)

TARGET_PIC_FLAG = -fpic
TARGET_PIE_FLAG = -fpie

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=20000000 -Tdata=20000000
  STRIP := $(CROSS)strip
else
  CFLAGS += $(TARGET_PIC_FLAG) $(TARGET_PIE_FLAG) -msingle-pic-base -mno-pic-data-is-text-relative
  # output .rel.* sections to make ELF position-independent
  LDFLAGS += -Wl,-q
  STRIP := $(PREFIX_PROJECT)/phoenix-rtos-build/scripts/strip.py $(CROSS)strip --strip-unneeded -R .rel.text
endif

CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

HAVE_MMU := n
