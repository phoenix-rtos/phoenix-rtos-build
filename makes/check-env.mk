# Makefile for Phoenix-RTOS 3
#
# Copyright 2024 Phoenix Systems
#

# check if the final build environment is sane
# when building components directly (omitting build.sh entry point) you might want to disable these checks

# Verify variables used for kernel compilation
ifndef HAVE_MMU
  ifneq ($(TARGET_FAMILY), host)
    $(error "HAVE_MMU is not set")
  endif
endif

ifeq ($(HAVE_MMU), y)
  ifneq ($(KERNEL_PHADDR),)
    $(error "KERNEL_PHADDR is set for MMU target, please check project configuration")
  endif
endif

ifeq ($(HAVE_MMU), n)
  ifeq ($(KERNEL_PHADDR),)
    $(error "KERNEL_PHADDR is not set for NOMMU target, please check project configuration")
  endif
endif
