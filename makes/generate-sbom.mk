# Makefile rules for emitting SBOM metadata fragment of a component
# The fragments are later collected by generate_sbom.py into the final CycloneDX SBOM
#
# input variables (read at include time):
# - NAME - component name
# - SBOM_TYPE - component kind: binary, static-lib, kernel, bootloader
# - SBOM_ARTIFACTS - built files representing the component (missing ones are ignored by generate_sbom.py)
# - SBOM_MAKEFILE_PATH - component's Makefile (its directory is scanned for copyright/licensing info)
# - SBOM_VERSION - optional component version (falls back to Phoenix-RTOS version)
# - SBOM_DEPS - names of components linked into this one
# - SBOM_PORT_LIBS - paths to port libraries linked into this component
# - LICENSE, CPE, PURL - optional component metadata
# - LOCAL_SBOM - optional CycloneDX SBOM(s) of third-party code vendored by the component,
#                resolved against LOCAL_DIR exactly like LOCAL_SRCS
# - LOCAL_DIR - component directory relative to the repository root (set by static-lib.mk/binary.mk)
#
# output variables:
# - SBOM_FRAG - path to the fragment, needs to be added as a prerequisite of the component target

SBOM_FRAG := $(BUILD_DIR)/$(NAME).sbom.json

SBOM_EXTRA := $(if $(LOCAL_SBOM),$(abspath $(addprefix $(LOCAL_DIR),$(LOCAL_SBOM))))

# Capture metadata at parse time via target-specific variables
$(SBOM_FRAG): SBOM_NAME := $(NAME)
$(SBOM_FRAG): SBOM_TYPE := $(SBOM_TYPE)
$(SBOM_FRAG): SBOM_ARTIFACTS := $(strip $(abspath $(SBOM_ARTIFACTS)))
$(SBOM_FRAG): SBOM_MAKEFILE_PATH := $(SBOM_MAKEFILE_PATH)
$(SBOM_FRAG): SBOM_EXTRA := $(SBOM_EXTRA)
$(SBOM_FRAG): SBOM_DEPS := $(strip $(SBOM_DEPS))
$(SBOM_FRAG): SBOM_PORT_LIBS := $(strip $(SBOM_PORT_LIBS))
$(SBOM_FRAG): SBOM_VERSION := $(SBOM_VERSION)
$(SBOM_FRAG): SBOM_CPE := $(CPE)
$(SBOM_FRAG): SBOM_PURL := $(PURL)
$(SBOM_FRAG): SBOM_LICENSE := $(LICENSE)

# Metadata may come from outside the Makefile (e.g. command line variables), so the fragment is always
# regenerated, but replaced only if changed.
.PHONY: sbom-fragment-force
$(SBOM_FRAG): $(SBOM_EXTRA) sbom-fragment-force
	@mkdir -p $(dir $@)
	@jq -n \
		--arg name '$(SBOM_NAME)' \
		--arg version '$(SBOM_VERSION)' \
		--arg type '$(SBOM_TYPE)' \
		--arg license '$(SBOM_LICENSE)' \
		--arg cpe '$(SBOM_CPE)' \
		--arg purl '$(SBOM_PURL)' \
		--arg deps '$(SBOM_DEPS)' \
		--arg ports_libs '$(SBOM_PORT_LIBS)' \
		--arg artifacts '$(SBOM_ARTIFACTS)' \
		--arg makefile_path '$(SBOM_MAKEFILE_PATH)' \
		--arg extra_sbom '$(SBOM_EXTRA)' \
		'{name: $$name, version: $$version, type: $$type, license: $$license, cpe: $$cpe, purl: $$purl, deps: $$deps, ports_libs: $$ports_libs, artifacts: $$artifacts, makefile_path: $$makefile_path, extra_sbom: $$extra_sbom}' > $@.tmp
	@if cmp -s $@.tmp $@; then rm $@.tmp; else echo 'SBOM $(SBOM_NAME)'; mv $@.tmp $@; fi
