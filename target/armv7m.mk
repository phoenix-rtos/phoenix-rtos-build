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
CFLAGS += $(OLVL)
CFLAGS += -Wall -Wstrict-prototypes -g
CFLAGS += -mthumb -fomit-frame-pointer -mno-unaligned-access
CFLAGS += -DNOMMU
CFLAGS += -fdata-sections -ffunction-sections

ifeq ($(TARGET_FAMILY), armv7m7)
  CFLAGS += -mcpu=cortex-m7 -mfloat-abi=hard -mfpu=fpv5-d16
else ifeq ($(TARGET_FAMILY), armv7m4)
  CFLAGS += -mcpu=cortex-m4 -mfloat-abi=soft -fstack-usage
else ifeq ($(TARGET_FAMILY), armv7m3)
  CFLAGS += -mcpu=cortex-m3 -mfloat-abi=soft -fstack-usage
endif

ifeq ($(TARGET_SUBFAMILY), stm32l152xd)
	RAM_SIZE=48
	VADDR_KERNEL_INIT=0800d000
	KERNEL_TARGET_DEFINE=-DNOMMU
else ifeq ($(TARGET_SUBFAMILY), stm32l152xe)
	RAM_SIZE=80
	VADDR_KERNEL_INIT=0800d000
	KERNEL_TARGET_DEFINE=-DNOMMU
else ifeq ($(TARGET_SUBFAMILY), stm32l4x6)
	RAM_SIZE=320
	VADDR_KERNEL_INIT=0800d000
	KERNEL_TARGET_DEFINE=-DNOMMU
else ifeq ($(TARGET_SUBFAMILY), imxrt105x)
	VADDR_KERNEL_INIT=0
	KERNEL_TARGET_DEFINE=-DNOMMU
else ifeq ($(TARGET_SUBFAMILY), imxrt106x)
	VADDR_KERNEL_INIT=0
	KERNEL_TARGET_DEFINE=-DNOMMU
else ifeq ($(TARGET_SUBFAMILY), imxrt117x)
	VADDR_KERNEL_INIT=0
	KERNEL_TARGET_DEFINE=-DNOMMU
else
	$(error Incorrect TARGET.)
endif


LDFLAGS := -z max-page-size=0x10 --gc-sections

ifeq ($(KERNEL), 1)
  CFLAGS += -DRAM_SIZE=$(RAM_SIZE) $(KERNEL_TARGET_DEFINE) -ffixed-r9
  LDFLAGS += -Tbss=20000000 -Tdata=20000000
  STRIP = $(CROSS)strip
else
  CFLAGS += -fpic -fpie -msingle-pic-base -mno-pic-data-is-text-relative
	# output .rel.* sections to make ELF position-independent
  LDFLAGS += -q
  STRIP = $(PREFIX_PROJECT)/phoenix-rtos-build/scripts/strip.py $(CROSS)strip --strip-unneeded -R .rel.text
endif

CXXFLAGS += $(filter-out -Wstrict-prototypes, $(CFLAGS))

AR = $(CROSS)ar
ARFLAGS = -r

LD = $(CROSS)ld

GCCLIB := $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)
CRTBEGIN := $(shell $(CC) $(CFLAGS) -print-file-name=crtbegin.o)
CRTEND := $(shell $(CC) $(CFLAGS) -print-file-name=crtend.o)
PHOENIXLIB := $(shell $(CC) $(CFLAGS) -print-file-name=libphoenix.a)
# The filter-out enables proper building because if libstdc++ is not available, LIBSTDCPP will be empty.
LIBSTDCPP := $(filter-out libstdc++.a, $(shell $(CXX) $(CXXFLAGS) -print-file-name=libstdc++.a))
# For arm, the implementation of exceptions, defined in libgcc, uses abort() from libphoenix
LDLIBS := $(LIBSTDCPP) --start-group $(PHOENIXLIB) $(GCCLIB) --end-group $(CRTBEGIN) $(CRTEND)


OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump
