# Makefile for Phoenix-RTOS 3
#
# Copyright 2026 Phoenix Systems
#

CALLY_PATH := $(SCRIPTS_PATH)/cally.py

DEPTH ?= 5
MODULE ?= $(CURDIR)

graph-caller:
	@mkdir -p $(PREFIX_BUILD)/graphs
	@echo "Generating searchable PDF graph for $(FUNC) (Max Depth: $(DEPTH))..."
	@# Find RTL files
	$(eval RTL_FILES := $(shell find $(PREFIX_O) -name "*.expand" 2>/dev/null))
	@if [ -z "$$(find $(PREFIX_O) -name "*.expand" -print -quit)" ]; then \
		echo "Error: No RTL files found in $(PREFIX_O)"; \
		exit 1; \
	fi
	@# Run graph-caller
	@python3 $(CALLY_PATH) --caller $(FUNC) --max-depth $(DEPTH) $(RTL_FILES) | \
		dot -Grankdir=LR -Tpdf -o $(PREFIX_BUILD)/graphs/$(FUNC)_$(notdir $(CURDIR))_caller_depth$(DEPTH).pdf
	@echo "Done. Saved to: $(PREFIX_BUILD)/graphs/$(FUNC)_$(notdir $(CURDIR))_caller_depth$(DEPTH).pdf"

graph-callee:
	@mkdir -p $(PREFIX_BUILD)/graphs
	@echo "Generating searchable PDF graph for $(FUNC) (Max Depth: $(DEPTH))..."
	@# Find RTL files and run grpahs
	$(eval RTL_FILES := $(shell find $(PREFIX_O) -name "*.expand" 2>/dev/null))
	@if [ -z "$$(find $(PREFIX_O) -name "*.expand" -print -quit)" ]; then \
		echo "Error: No RTL files found in $(PREFIX_O)"; \
		exit 1; \
	fi
	@# Run graph-callee
	@python3 $(CALLY_PATH) --callee $(FUNC) --max-depth $(DEPTH) $(RTL_FILES) | \
		dot -Grankdir=LR -Tpdf -o $(PREFIX_BUILD)/graphs/$(FUNC)_$(notdir $(CURDIR))_callee_depth$(DEPTH).pdf
	@echo "Done. Saved to: $(PREFIX_BUILD)/graphs/$(FUNC)_$(notdir $(CURDIR))_callee_depth$(DEPTH).pdf"

