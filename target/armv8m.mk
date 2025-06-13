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

# soft FPU for now, no support in kernel for hard FPU
CFLAGS += -mfloat-abi=soft -fstack-usage

MCX_USE_CPU1 ?= n
MCX_CPU0_RST_ADDR ?= n
KERNEL_DATA_PHADDR ?= 0x20000000

ifeq ($(TARGET_FAMILY), armv8m55)
  CFLAGS += -mcpu=cortex-m55
else ifeq ($(TARGET_FAMILY), armv8m33)
  ifeq ($(MCX_USE_CPU1), y)
    CFLAGS += -mcpu=cortex-m33+nodsp
  else
    CFLAGS += -mcpu=cortex-m33
  endif
endif

VADDR_KERNEL_INIT := $(KERNEL_PHADDR)

LDFLAGS := -Wl,-z,max-page-size=0x10

ifeq ($(KERNEL), 1)
  CFLAGS += -ffixed-r9
  LDFLAGS += -Tbss=$(KERNEL_DATA_PHADDR) -Tdata=$(KERNEL_DATA_PHADDR)
  STRIP := $(CROSS)strip

  ifeq ($(MCX_USE_CPU1), y)
    CFLAGS += -DMCX_USE_CPU1
  endif

  ifneq ($(MCX_CPU0_RST_ADDR),n)
    CFLAGS += -DMCX_CPU0_RST_ADDR=$(MCX_CPU0_RST_ADDR) -DMCX_CHECK_ADDR=$(MCX_CHECK_ADDR)
  endif
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
