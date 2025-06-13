# Makefile for Phoenix-RTOS 3
#
# Copyright 2021 Phoenix Systems
#

# checking allowed TARGETs

# ARMv7 Cortex Mx
TARGETS_ARM7CORTEXM := \
	armv7m3-stm32l152xd \
	armv7m3-stm32l152xe \
	armv7m4-stm32l4x6 \
	armv7m7-imxrt105x \
	armv7m7-imxrt106x \
	armv7m7-imxrt117x

TARGETS := $(TARGETS_ARM7CORTEXM)
ifneq (,$(filter $(TARGETS_ARM7CORTEXM),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv7m
endif

# ARMv8 Cortex Mx
TARGETS_ARM8CORTEXM := \
  armv8m33-mcxn94x \
  armv8m55-stm32n6

TARGETS += $(TARGETS_ARM8CORTEXM)
ifneq (,$(filter $(TARGETS_ARM8CORTEXM),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv8m
endif

# ARM Cortex Ax
TARGETS_ARMCORTEXA := \
	armv7a7-imx6ull \
	armv7a9-zynq7000

TARGETS += $(TARGETS_ARMCORTEXA)
ifneq (,$(filter $(TARGETS_ARMCORTEXA),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv7a
endif

# ARMv8 Cortex A
TARGETS_ARMCORTEX8A := \
	aarch64a53-zynqmp

TARGETS += $(TARGETS_ARMCORTEX8A)
ifneq (,$(filter $(TARGETS_ARMCORTEX8A),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= aarch64
endif

# ARMv8 Cortex R
TARGETS_ARM8CORTEXR := \
  armv8r52-mps3an536

TARGETS += $(TARGETS_ARM8CORTEXR)
ifneq (,$(filter $(TARGETS_ARM8CORTEXR),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv8r
endif

# ARMv7 Cortex R
TARGETS_ARM7CORTEXR := \
  armv7r5f-zynqmp

TARGETS += $(TARGETS_ARM7CORTEXR)
ifneq (,$(filter $(TARGETS_ARM7CORTEXR),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= armv7r
endif

# IA32
TARGETS_IA32 := ia32-generic

TARGETS += $(TARGETS_IA32)
ifneq (,$(filter $(TARGETS_IA32),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= ia32
endif

# RISCV64
TARGETS_RISCV64 := \
	riscv64-generic \
	riscv64-grfpga \
	riscv64-gr765

TARGETS += $(TARGETS_RISCV64)
ifneq (,$(filter $(TARGETS_RISCV64),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= riscv64
endif

TARGETS += host-generic
ifeq ($(TARGET_FAMILY), host)
  TARGET_SUFF ?= host
endif

# SPARCV8 LEON
TARGETS_SPARC := \
  sparcv8leon-gr716 \
  sparcv8leon-gr712rc \
  sparcv8leon-gr740 \
  sparcv8leon-generic

TARGETS += $(TARGETS_SPARC)
ifneq (,$(filter $(TARGETS_SPARC),$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)))
  TARGET_SUFF ?= sparcv8leon
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

include $(MAKES_PATH)/../target/$(TARGET_SUFF).mk
