# Makefile for Phoenix-RTOS 3
#
# Copyright 2021 Phoenix Systems
#

# checking allowed TARGETs

# ARMV7 Cortex Mx
TARGETS_ARMV7CORTEXM := \
	armv7m3-stm32l152xd \
	armv7m3-stm32l152xe \
	armv7m4-stm32l4x6 \
	armv7m7-imxrt105x \
	armv7m7-imxrt106x \
	armv7m7-imxrt117x

TARGETS := $(TARGETS_ARMV7CORTEXM)
ifneq (,$(filter $(TARGETS_ARMV7CORTEXM),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv7m
endif

# ARMV8 Cortex Mx
TARGETS_ARMV8CORTEXM := \
	armv8m33-nrf9160

TARGETS += $(TARGETS_ARMV8CORTEXM)
ifneq (,$(filter $(TARGETS_ARMV8CORTEXM),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv8m
endif

# ARMV7 Cortex Ax
TARGETS_ARMCORTEXA := \
	armv7a7-imx6ull \
	armv7a9-zynq7000

TARGETS += $(TARGETS_ARMCORTEXA)
ifneq (,$(filter $(TARGETS_ARMCORTEXA),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv7a
endif

# IA32
TARGETS_IA32 := ia32-generic

TARGETS += $(TARGETS_IA32)
ifneq (,$(filter $(TARGETS_IA32),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= ia32
endif

#RISCV64
TARGETS_RISCV64 := riscv64-generic

TARGETS += $(TARGETS_RISCV64)
ifneq (,$(filter $(TARGETS_RISCV64),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= riscv64
endif

TARGETS += host-generic
ifeq ($(TARGET_FAMILY), host)
  TARGET_SUFF ?= host
endif

SPACE :=
SPACE +=
define LF


endef

# Check target
ifeq (,$(filter $(TARGETS),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  ifeq (,$(TARGET))
    MESSAGE := Empty TARGET
  else
    MESSAGE := Incorrect TARGET $(TARGET_FAMILY)-$(TARGET_SUBFAMILY)
  endif

  $(error $(MESSAGE)$(LF)Available targets:$(LF)$(subst $(SPACE),$(LF),$(sort $(TARGETS))$(LF)))
endif

include $(MAKES_PATH)/../Makefile.$(TARGET_SUFF)
