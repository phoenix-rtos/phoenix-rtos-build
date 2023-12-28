#
# Makefile for Phoenix-RTOS 3
#
# SPARCv8 LEON3 options
#
# Copyright 2022, 2023 Phoenix Systems
#
# %LICENSE%
#

CROSS ?= sparc-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2
CFLAGS += -mcpu=leon3

LDFLAGS :=

ifeq ($(TARGET_SUBFAMILY), gr716)
  VADDR_KERNEL_INIT := 31000000
  CPPFLAGS := -DNOMMU
  CFLAGS += -msoft-float

  ifeq ($(KERNEL), 1)
    LDFLAGS += -Wl,-z,max-page-size=0x200 -Tbss=40001800 -Tdata=40001800 -Wl,--section-start=.rodata=40000000
    STRIP := $(CROSS)strip
  else
    CFLAGS += -fPIC -fPIE -mno-pic-data-is-text-relative -mpic-register=g6
    LDFLAGS += -Wl,-q
    STRIP := $(CROSS)strip --strip-unneeded -R .rela.text
  endif

else ifeq ($(TARGET_SUBFAMILY), gr712rc)
  ifeq ($(KERNEL), 1)
    CFLAGS += -msoft-float
  endif
  STRIP := $(CROSS)strip
  VADDR_KERNEL_INIT := 0xc0000000
  CFLAGS += -mfix-gr712rc -DLEON3_TN_0018_FIX
  LDFLAGS += -Wl,-z,max-page-size=0x1000

else
  $(error Incorrect TARGET.)
endif

AR := $(CROSS)ar
ARFLAGS = -r

LD := $(CROSS)gcc
LDFLAGS_PREFIX := -Wl,

CXXFLAGS := $(CFLAGS)

OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
