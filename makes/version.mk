# Makefile for Phoenix-RTOS 3
#
# Phoenix-RTOS version: PHOENIX_VER and PHOENIX_VER_{MAJOR,MINOR,PATCH,TAG,BUILD,NUM} (make and recipe
# environment variables) and the <phoenix/version.h> header, from OS-VERSION in the project root - the only
# source of the version, updated on releases
#
# Copyright 2026 Phoenix Systems
#

OS_VERSION_FILE ?= $(PREFIX_PROJECT)/OS-VERSION

ifeq ($(wildcard $(OS_VERSION_FILE)),)
  $(error $(OS_VERSION_FILE) not found)
endif

include $(OS_VERSION_FILE)

# Validation:
# - MAJOR/MINOR/PATCH: 0-999, without leading zeros, must not be empty
# - TAG/BUILD: alphanumerics and a dot, may be empty

PHOENIX_VER_RE_NUM := 0|[1-9][0-9]{0,2}
PHOENIX_VER_RE_TEXT := [0-9A-Za-z.]*

# $(call phoenix_ver_check,VAR,ERE)
phoenix_ver_check = $(if $(shell printf '%s\n' '$($(1))' | grep -qxE '$(2)' && echo ok),,\
  $(error $(OS_VERSION_FILE): $(1) must match '$(2)', got '$($(1))'))

$(foreach v,VER_MAJOR VER_MINOR VER_PATCH,$(call phoenix_ver_check,$(v),$(PHOENIX_VER_RE_NUM)))
$(foreach v,VER_TAG VER_BUILD,$(call phoenix_ver_check,$(v),$(PHOENIX_VER_RE_TEXT)))

PHOENIX_VER_MAJOR := $(VER_MAJOR)
PHOENIX_VER_MINOR := $(VER_MINOR)
PHOENIX_VER_PATCH := $(VER_PATCH)
PHOENIX_VER_TAG := $(VER_TAG)
PHOENIX_VER_BUILD := $(VER_BUILD)
PHOENIX_VER := $(VER_MAJOR).$(VER_MINOR).$(VER_PATCH)$(if $(VER_TAG),-$(VER_TAG))$(if $(VER_BUILD),+$(VER_BUILD))
PHOENIX_VER_NUM := $(shell echo $$(($(VER_MAJOR) * 1000000 + $(VER_MINOR) * 1000 + $(VER_PATCH))))

PHOENIX_VER_VARS := PHOENIX_VER PHOENIX_VER_MAJOR PHOENIX_VER_MINOR PHOENIX_VER_PATCH PHOENIX_VER_TAG PHOENIX_VER_BUILD \
  PHOENIX_VER_NUM
export $(PHOENIX_VER_VARS)

define PHOENIX_VER_H_CONTENT
/* Phoenix-RTOS version - generated from OS-VERSION by phoenix-rtos-build/makes/version.mk, do not edit */

#ifndef _PHOENIX_VERSION_H_
#define _PHOENIX_VERSION_H_

#define PHOENIX_VER       "$(PHOENIX_VER)"
#define PHOENIX_VER_MAJOR $(PHOENIX_VER_MAJOR)
#define PHOENIX_VER_MINOR $(PHOENIX_VER_MINOR)
#define PHOENIX_VER_PATCH $(PHOENIX_VER_PATCH)
#define PHOENIX_VER_TAG   "$(PHOENIX_VER_TAG)"
#define PHOENIX_VER_BUILD "$(PHOENIX_VER_BUILD)"

/* MAJOR * 1000000 + MINOR * 1000 + PATCH, compare with PHOENIX_VER_MAKE(), e.g.
 * #if PHOENIX_VER_NUM >= PHOENIX_VER_MAKE(3, 4, 0) - also true for 3.4.0-dev and 3.4.0-rc.N */
#define PHOENIX_VER_NUM                       $(PHOENIX_VER_NUM)L
#define PHOENIX_VER_MAKE(major, minor, patch) ((major) * 1000000L + (minor) * 1000L + (patch))

#endif
endef

# A header and not -D flags: string macros don't survive EXPORT_CFLAGS into ports, and a header is tracked
# by the dependency files - rewritten only when the content changes, it rebuilds just its users.
# It is not written concurrently: sub-makes see the same content, parallel builds of one TARGET are unsupported.
PHOENIX_VER_H_DIR := $(PREFIX_BUILD)/os-version
PHOENIX_VER_H := $(PHOENIX_VER_H_DIR)/phoenix/version.h
CFLAGS += -I$(PHOENIX_VER_H_DIR)
CXXFLAGS += -I$(PHOENIX_VER_H_DIR)

ifneq ($(file <$(PHOENIX_VER_H)),$(PHOENIX_VER_H_CONTENT))
  $(shell mkdir -p "$(dir $(PHOENIX_VER_H))")
  $(file >$(PHOENIX_VER_H),$(PHOENIX_VER_H_CONTENT))
endif
