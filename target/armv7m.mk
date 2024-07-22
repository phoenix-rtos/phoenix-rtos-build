#
# Makefile for libphoenix
#
# ARMv7 (Cortex-M3/M4) options
#
# Copyright 2018, 2020 Phoenix Systems
#

CROSS ?= arm-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

# common Cortex-M CFLAGS
OLVL ?= -O2
CFLAGS += -mthumb -fomit-frame-pointer -mno-unaligned-access -fstack-usage

ifeq ($(TARGET_FAMILY), armv7m7)
  CFLAGS += -mcpu=cortex-m7 -mfloat-abi=hard -mfpu=fpv5-d16
else ifeq ($(TARGET_FAMILY), armv7m4)
  CFLAGS += -mcpu=cortex-m4 -mfloat-abi=soft
else ifeq ($(TARGET_FAMILY), armv7m3)
  CFLAGS += -mcpu=cortex-m3 -mfloat-abi=soft
endif

VADDR_KERNEL_INIT := $(KERNEL_PHADDR)

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=20000000 -Tdata=20000000
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
