#
# Makefile for Phoenix-RTOS 3
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

TARGET_PIC_FLAG = -fpic
TARGET_PIE_FLAG = -fpie

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=20000000 -Tdata=20000000
  STRIP := $(CROSS)strip
else
  # NOTE: More information about this flags can be found in armv8r.mk
  CFLAGS += $(TARGET_PIE_FLAG) -fpic -mfdpic -Wa,--fdpic
  TARGET_STATIC_FLAG := -static-pie
  LDFLAGS += -Wl,--version-script="$(hide.map)" -pie -Wl,-marmelf_phoenix_fdpiceabi
  STRIP := $(CROSS)strip
endif

CXXFLAGS := $(CFLAGS)

AR := $(CROSS)ar
ARFLAGS := -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

HAVE_MMU := n
HAVE_SHLIB := n
