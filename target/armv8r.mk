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

VADDR_KERNEL_INIT := $(KERNEL_PHADDR)

TARGET_PIC_FLAG = -fpic
TARGET_PIE_FLAG = -fpie

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=10014000 -Tdata=10014000
  STRIP := $(CROSS)strip
else
  CFLAGS += $(TARGET_PIE_FLAG) -fpic -mfdpic -Wa,--fdpic
  # NOTE: without -static-pie a .rofixup section is generated and text relocations are required.
  TARGET_STATIC_FLAG := -static-pie
  # NOTE: version script needed as without it GCC generates FUNCTION_DESCRIPTOR relocations in static binaries which are nonsense
  # FIXME: -static-libgcc neeeded due to bad compilation of shared libgcc
  #        bad compilation stems from the fact that we do not have real multilib on ARM.
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
HAVE_SHLIB := y
LIBPHOENIX_PIC := y
LIBPHOENIX_SHARED := y
