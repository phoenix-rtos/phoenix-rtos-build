#
# Build system
#
# Port versioning assertions
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

ifdef PORTS_SUPPORTED_VERSIONS
  PORTS_INVALID_VERSIONS_LOCAL := $(filter-out $(PORTS_SUPPORTED_VERSIONS), $(LOCAL_PORTS_VERSIONS))

  ifneq ($(PORTS_INVALID_VERSIONS_LOCAL), )
    $(error Invalid versions in LOCAL_PORTS_VERSIONS: $(PORTS_INVALID_VERSIONS_LOCAL))
  endif
endif

# vim:expandtab:ts=2:sw=2
