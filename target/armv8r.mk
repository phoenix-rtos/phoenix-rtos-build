#
# Makefile for Phoenix-RTOS 3
#
# ARMv8 Cortex-R options
#
# Copyright 2024 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

# common Cortex-R CFLAGS
OLVL ?= -O2
CFLAGS += -mthumb -fomit-frame-pointer -mno-unaligned-access

ifeq ($(TARGET_FAMILY), armv8r52)
  CFLAGS += -mcpu=cortex-r52 -mtune=cortex-r52 -mfpu=neon-vfpv3 -mfloat-abi=hard
endif

KERNEL_INIT_START := $(KERNEL_PHADDR)

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=10014000 -Tdata=10014000
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
