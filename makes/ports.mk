#
# Build system
#
# Makefile-level support for port versioning
#
# Copyright 2025, 2026 Phoenix Systems
# Author: Hubert Badocha, Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

# TODO: invoke port_manager via $(shell ...) here instead to discover supported versions?
PORTS_SUPPORTED_VERSIONS :=
PORTS_SUPPORTED_VERSIONS += openssl=1.1.1a


PORTS_DEFAULT_VERSIONS :=
PORTS_DEFAULT_VERSIONS += openssl=1.1.1a


PORTS_VERSIONS := $(PORTS_DEFAULT_VERSIONS) $(PORTS_DEFAULT_VERSIONS_PROJECT)


PORTS_INVALID_VERSIONS=$(filter-out $(PORTS_SUPPORTED_VERSIONS),$(PORTS_DEFAULT_VERSIONS))

ifneq ($(PORTS_INVALID_VERSIONS), )
  $(error Invalid versions in PORTS_DEFAULT_VERSIONS: $(PORTS_INVALID_VERSIONS))
endif


PORTS_INVALID_VERSIONS_PROJECT=$(filter-out $(PORTS_SUPPORTED_VERSIONS),$(PORTS_DEFAULT_VERSIONS_PROJECT))

ifneq ($(PORTS_INVALID_VERSIONS_PROJECT), )
  $(error Invalid versions in PORTS_DEFAULT_VERSIONS_PROJECT: $(PORTS_INVALID_VERSIONS_PROJECT))
endif


# Obtain unique ports (without versions) from PORTS_VERSIONS_LIST
# $(call ports_uniq, PORTS_VERSIONS_LIST)
define ports_uniq
$(sort $(foreach PORT_VERSION, $(1),$(word 1,$(subst =, ,$(PORT_VERSION)))))
endef


# Use only the last definition of each port from PORTS_VERSIONS_LIST
# $(call ports_last_version, PORTS_VERSIONS_LIST)
define ports_last_version
$(foreach PORT\
  ,$(call ports_uniq, $(1))\
  ,$(lastword $(filter $(PORT)=%, $(1))))
endef


define check_default_versions
$(foreach PORT\
  ,$(PORTS_VERSIONS)\
  ,$(call check_default_version, $(PORT)))
endef


define ports_versions
$(call ports_last_version,$(PORTS_VERSIONS) $(LOCAL_PORTS_VERSIONS))
endef


define port_to_folder
$(PREFIX_BUILD_VERSIONED)/$(subst =,-,$(strip $(1)))
endef


define ports_iflags
$(foreach PORT, $(call ports_versions), -I$(call port_to_folder,$(PORT))/include)
endef


define ports_ldir
$(foreach PORT, $(call ports_versions), $(call port_to_folder,$(PORT))/lib)
endef

# vim:expandtab:ts=2:sw=2
