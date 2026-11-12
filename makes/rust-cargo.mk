# Makefile rules shared by rust-binary.mk and rust-test.mk: the cargo
# configuration of a crate and its unit tests
#
# Everything `cargo test` builds for the crate forms the unit test test-<NAME>,
# registered like a test-binary.mk component:
# - test-<NAME>          builds the test executables (cargo test --no-run), named
#                        as in scripts/cargo-test-list.py
# - test-<NAME>-install  installs them into /bin, where phoenix-rtos-tests runs them
# - test-<NAME>-run      runs `cargo test` on the target through RUST_RUNNER
#
# Cargo recipes are marked with `+` so that cargo joins make's jobserver; other
# rustc calls run with MAKEFLAGS cleared, as they would warn about its missing fds.

ifeq ($(origin LOCAL_DIR), undefined)
  CLIENT_MAKES := $(filter-out %.d,$(filter $(TOPDIR)/%,$(abspath $(MAKEFILE_LIST))))
  LOCAL_DIR := $(patsubst $(TOPDIR)/%,%,$(dir $(lastword $(CLIENT_MAKES))))
endif

LOCAL_MANIFEST ?= Cargo.toml

# per-component copies, as LOCAL_* are reset by the including makefile
MANIFEST.$(NAME) := $(abspath $(LOCAL_DIR)$(LOCAL_MANIFEST))
CARGO_DIR.$(NAME) := $(PREFIX_O)$(NAME).cargo
CARGO_FLAGS.$(NAME) := $(LOCAL_CARGO_FLAGS)
# outside CARGO_DIR, which the binary's clean removes
TEST_LIST.$(NAME) := $(PREFIX_O)test-$(NAME).list

DEPS += $(DEP_LIBS)

# `-l static=` so that rustc does not look for a shared object; RUSTFLAGS_TARGET
# is expanded late, as it queries rustc
LOCAL_RUSTFLAGS.$(NAME) := $(patsubst %,-l static=%,$(LIBS) $(DEP_LIBS)) $(LOCAL_RUSTFLAGS)
RUSTFLAGS.$(NAME) = $(strip $(RUSTFLAGS_TARGET) $(LOCAL_RUSTFLAGS.$(NAME)))

# cargo is configured through the environment, so nothing is written to the
# source tree; <NAME>-cargo-env prints the same settings for manual use
CARGO_VARS.$(NAME) = \
	$(RUST_CARGO_VARS) \
	CARGO_TARGET_DIR="$(CARGO_DIR.$(NAME))" \
	CARGO_BUILD_BUILD_DIR="$(RUST_BUILD_DIR)" \
	CARGO_TARGET_$(RUST_TARGET_ENV)_RUSTFLAGS="$(RUSTFLAGS.$(NAME))"

CARGO_ENV.$(NAME) = CARGO_TERM_QUIET=true $(CARGO_VARS.$(NAME))

CARGO_ARGS.$(NAME) = --manifest-path "$(MANIFEST.$(NAME))" --profile "$(RUST_PROFILE)" $(RUST_VARIANT_CARGO_FLAGS) $(CARGO_FLAGS.$(NAME))

define CHECK_RUST_ENV
	$(SIL)if [ -z "$(RUST_TARGET)" ]; then \
		echo "$(NAME): RUST_TARGET is not set for TARGET=$(TARGET); see phoenix-rtos-build/target/$(TARGET_SUFF).mk" >&2; \
		exit 1; \
	fi; \
	if ! MAKEFLAGS= "$(RUSTC)" --print target-list 2>/dev/null | grep -qx "$(RUST_TARGET)"; then \
		echo "$(NAME): no rustc for $(RUST_TARGET) at '$(RUSTC)' - set RUST_TOOLCHAIN_DIR to a Phoenix Rust toolchain" >&2; \
		exit 1; \
	fi; \
	if ! command -v "$(CARGO)" >/dev/null 2>&1; then \
		echo "$(NAME): no cargo at '$(CARGO)' - set CARGO to a cargo binary" >&2; \
		exit 1; \
	fi
endef

# the first build of a target with std from sources takes a while
define NOTE_STD_BUILD
	$(SIL)if [ -n "$(findstring -Zbuild-std,$(RUST_VARIANT_CARGO_FLAGS))" ]; then \
		if [ -z "$$(find "$(RUST_BUILD_DIR)/$(RUST_TARGET)/$(RUST_PROFILE_DIR)" -name 'libstd-*.rlib' -print -quit 2>/dev/null)" ]; then \
			echo "compiling std from sources"; \
		fi; \
	fi
endef

.PHONY: $(NAME)-cargo-env test-$(NAME) test-$(NAME)-install test-$(NAME)-run test-$(NAME)-clean

# usage: eval "$(make -C .. <NAME>-cargo-env)" && cargo test
$(NAME)-cargo-env:
	@for kv in $(CARGO_VARS.$(NAME)); do \
		printf "export %s='%s'\n" "$${kv%%=*}" "$${kv#*=}"; \
	done

# The list holds "<test name> <executable>" lines. Executables are copied only
# when changed, which keeps stripping and installing quiet on a no-op build.
test-$(NAME): | $(DEPS)
	@printf "CARGO %-22s\n" "$(NAME) tests"
	$(CHECK_RUST_ENV)
	$(NOTE_STD_BUILD)
	@mkdir -p "$(CARGO_DIR.$(NAME))" "$(PREFIX_PROG)" "$(PREFIX_PROG_STRIPPED)"
	+$(SIL)$(CARGO_ENV.$(NAME)) $(CARGO) test $(CARGO_ARGS.$(NAME)) --no-run \
		--message-format=json-render-diagnostics > "$(CARGO_DIR.$(NAME))/tests.json"
	$(SIL)$(MAKES_PATH)/../scripts/cargo-test-list.py "$(CARGO_DIR.$(NAME))/tests.json" "$(NAME)" > "$(TEST_LIST.$(NAME))"
	$(SIL)while read -r test exe; do \
		if ! cmp -s "$$exe" "$(PREFIX_PROG)$$test"; then \
			printf "LD  %-24s\n" "$$test"; \
			cp -p "$$exe" "$(PREFIX_PROG)$$test"; \
			printf "STR %-24s\n" "$$test"; \
			$(STRIP) -o "$(PREFIX_PROG_STRIPPED)$$test" "$(PREFIX_PROG)$$test" || exit 1; \
		fi; \
	done < "$(TEST_LIST.$(NAME))"

test-$(NAME)-install: test-$(NAME)
	$(SIL)while read -r test exe; do \
		src="$(if $(ROOTFS_INSTALL_UNSTRIPPED),$(PREFIX_PROG),$(PREFIX_PROG_STRIPPED))$$test"; \
		dst="$(PREFIX_ROOTFS)/bin/$$test"; \
		if ! cmp -s "$$src" "$$dst"; then \
			printf "INSTALL %s\n" "/bin/$$test"; \
			mkdir -p "$${dst%/*}" && cp -p "$$src" "$$dst" || exit 1; \
		fi; \
	done < "$(TEST_LIST.$(NAME))"

test-$(NAME)-run:
	@printf "CARGO %-22s\n" "$(NAME) test"
	$(CHECK_RUST_ENV)
	$(NOTE_STD_BUILD)
	$(SIL)if [ -z "$(RUST_RUNNER)" ]; then \
		echo "test-$(NAME): RUST_RUNNER is not set" >&2; \
		exit 1; \
	fi
	+$(SIL)$(CARGO_ENV.$(NAME)) $(CARGO) test $(CARGO_ARGS.$(NAME))

test-$(NAME)-clean:
	@echo "cleaning test-$(NAME)"
	$(SIL)if [ -f "$(TEST_LIST.$(NAME))" ]; then \
		while read -r test exe; do \
			rm -f "$(PREFIX_PROG)$$test" "$(PREFIX_PROG_STRIPPED)$$test"; \
		done < "$(TEST_LIST.$(NAME))"; \
	fi
	@rm -rf "$(TEST_LIST.$(NAME))" "$(CARGO_DIR.$(NAME))"

# necessary for NAME to be correctly set in the recipes
$(NAME)-cargo-env test-$(NAME) test-$(NAME)-install test-$(NAME)-run test-$(NAME)-clean: NAME:=$(NAME)

# tests are not a part of the product (see test-binary.mk); Rust ones take part
# in the test goals only with RUST_ENABLE=y, see DEFAULT_TEST_COMPONENTS
TEST_COMPONENTS += test-$(NAME)
RUST_TEST_COMPONENTS += test-$(NAME)

# vim:expandtab:ts=2:sw=2
