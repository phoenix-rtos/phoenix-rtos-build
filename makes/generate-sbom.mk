# The target output for this module's metadata
SBOM_FRAG := $(BUILD_DIR)/$(NAME).sbom.json
$(SBOM_FRAG)-install: $(SBOM_FRAG) ;

# # Ensure the fragment is built when the library is built
$(NAME): $(SBOM_FRAG)

# Capture metadata at parse time via target-specific variables
$(SBOM_FRAG): SBOM_NAME := $(NAME)
$(SBOM_FRAG): SBOM_DEPS := $(DEPS)
$(SBOM_FRAG): SBOM_SRCS := $(SRCS)
$(SBOM_FRAG): SBOM_HEADERS := $(HEADERS)
$(SBOM_FRAG): SBOM_LIBS := $(LIBS)
$(SBOM_FRAG): SBOM_PORTS_LIBS := $(RESOLVED_PORT_LIBS)
$(SBOM_FRAG): SBOM_VERSION := $(VERSION)
$(SBOM_FRAG): SBOM_CPE := $(CPE)
$(SBOM_FRAG): SBOM_PURL := $(PURL)
$(SBOM_FRAG): SBOM_LICENSE := $(LICENSE)

# Generate the JSON fragment
$(SBOM_FRAG): $(SBOM_ARTIFACT)
	@echo 'SBOM $@'
	@mkdir -p $(dir $@)
	@jq -n \
		--arg name '$(SBOM_NAME)' \
		--arg version '$(SBOM_VERSION)' \
		--arg type '$(SBOM_TYPE)' \
		--arg license '$(SBOM_LICENSE)' \
		--arg cpe '$(SBOM_CPE)' \
		--arg purl '$(SBOM_PURL)' \
		--arg deps '$(SBOM_DEPS)' \
		--arg libs '$(SBOM_LIBS)' \
		--arg ports_libs '$(SBOM_PORTS_LIBS)' \
		--arg srcs '$(SBOM_SRCS)' \
		--arg headers '$(SBOM_HEADERS)' \
		--arg makefile_path '$(SBOM_MAKEFILE_PATH)' \
		'{name: $$name, version: $$version, type: $$type, license: $$license, cpe: $$cpe, purl: $$purl, deps: $$deps, libs: $$libs, ports_libs: $$ports_libs, srcs: $$srcs, headers: $$headers, makefile_path: $$makefile_path}' > $@
