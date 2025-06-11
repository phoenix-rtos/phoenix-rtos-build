#
# Makefile for Phoenix-RTOS 3
#
# SPARCv8 LEON options
#
# Copyright 2022-2024 Phoenix Systems
#
# %LICENSE%
#

CROSS ?= sparc-phoenix-

CC := $(CROSS)gcc
CXX := $(CROSS)g++

OLVL ?= -O2

# LEON4 CPU (GR740) still uses `-mcpu=leon3` flag
CFLAGS += -mcpu=leon3

LDFLAGS :=

ifeq ($(TARGET_SUBFAMILY), gr716)
  VADDR_KERNEL_INIT := $(KERNEL_PHADDR)

  CFLAGS += -msoft-float

  ifeq ($(KERNEL), 1)
    LDFLAGS += -Wl,-z,max-page-size=0x200 -Tbss=40001a00 -Tdata=40001a00 -Wl,--section-start=.rodata=40000000
    STRIP := $(CROSS)strip
    CPPFLAGS += -DLEON_USE_PWR
  else
    CFLAGS += -fPIC -fPIE -mno-pic-data-is-text-relative -mpic-register=g6
    LDFLAGS += -Wl,-q
    STRIP := $(CROSS)strip --strip-unneeded -R .rela.text
  endif

  HAVE_MMU := n

else ifeq ($(TARGET_SUBFAMILY), gr712rc)
  ifeq ($(KERNEL), 1)
    CFLAGS += -msoft-float
  endif
  STRIP := $(CROSS)strip
  VADDR_KERNEL_INIT := 0xc0000000
  CFLAGS += -mfix-gr712rc
  CPPFLAGS += -DLEON_TN_0018_FIX
  LDFLAGS += -Wl,-z,max-page-size=0x1000

  HAVE_MMU := y
else ifeq ($(TARGET_SUBFAMILY), generic)
  ifeq ($(KERNEL), 1)
    # `mno-user-mode` flag affects only `casa` instruction
    # funnily enough, real hw can run without it
    # but qemu will throw an exception
    CFLAGS += -msoft-float -mno-user-mode
  endif

  STRIP := $(CROSS)strip
  VADDR_KERNEL_INIT := 0xc0000000
  LDFLAGS += -Wl,-z,max-page-size=0x1000

  HAVE_MMU := y

else ifeq ($(TARGET_SUBFAMILY), gr740)
  ifeq ($(KERNEL), 1)
    CFLAGS += -msoft-float
    CPPFLAGS += -DLEON_USE_PWR
  endif
  STRIP := $(CROSS)strip
  VADDR_KERNEL_INIT := 0xc0000000
  LDFLAGS += -Wl,-z,max-page-size=0x1000

  HAVE_MMU := y

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
