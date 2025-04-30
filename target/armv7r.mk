#
# Makefile for Phoenix-RTOS 3
#
# ARMv7 Cortex-R options
#
# Copyright 2025 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

# common Cortex-R CFLAGS
OLVL ?= -O2
CFLAGS += -mthumb -fomit-frame-pointer -mno-unaligned-access

ifeq ($(TARGET_FAMILY), armv7r5f)
  CFLAGS += -mcpu=cortex-r5 -mtune=cortex-r5 -mfpu=vfpv3-d16 -mfloat-abi=hard
endif

ifeq ($(VADDR_KERNEL_DATA), )
  VADDR_KERNEL_DATA := 0x100000
endif

VADDR_KERNEL_INIT := $(KERNEL_PHADDR)
KERNEL_DATA_PHADDR ?= 0x100000

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=$(KERNEL_DATA_PHADDR) -Tdata=$(KERNEL_DATA_PHADDR)
  STRIP := $(CROSS)strip
else
  CFLAGS += -fpic -fpie -msingle-pic-base -mno-pic-data-is-text-relative
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
