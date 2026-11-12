# Makefile for Phoenix-RTOS 3
#
# Copyright 2026 Phoenix Systems
#
# Setting up the Rust toolchain
#
# The Rust toolchain is not part of phoenix-rtos-toolchain: point
# RUST_TOOLCHAIN_DIR at a rustc sysroot, or set RUSTC/CARGO directly.

# Rust components and their tests are opt-in
RUST_ENABLE ?= n

# a toolchain without cargo is driven by the host's one
ifneq ($(RUST_TOOLCHAIN_DIR),)
  RUSTC ?= $(abspath $(RUST_TOOLCHAIN_DIR))/bin/rustc
  CARGO ?= $(or $(wildcard $(abspath $(RUST_TOOLCHAIN_DIR))/bin/cargo),cargo)
endif
RUSTC ?= rustc
CARGO ?= cargo

# binaries are stripped separately, so this only selects optimisation
RUST_PROFILE ?= release

# Build variant:
#   checked (DEBUG=1) - prebuilt std, debug assertions and overflow checks
#   release (default) - std rebuilt (-Zbuild-std) without debug assertions and
#                       with only RUST_STD_FEATURES, for much smaller binaries
# Add "backtrace" to RUST_STD_FEATURES for RUST_BACKTRACE support.
# RUST_BUILD_STD=y makes checked rebuild std too, with the prebuilt std's
# features, so that both variants pick up a changed rust-src.
ifeq ($(DEBUG), 1)
  RUST_VARIANT ?= checked
else
  RUST_VARIANT ?= release
endif
RUST_STD_FEATURES ?= panic-unwind

ifeq ($(RUST_VARIANT), checked)
  RUST_VARIANT_CARGO_FLAGS = --config 'profile.$(RUST_PROFILE).debug-assertions=true' \
    --config 'profile.$(RUST_PROFILE).overflow-checks=true'
  RUST_VARIANT_ENV :=
  RUST_VARIANT_RUSTFLAGS :=
  ifeq ($(RUST_BUILD_STD), y)
    RUST_VARIANT_CARGO_FLAGS += -Zbuild-std=std,panic_abort -Zbuild-std-features="backtrace panic-unwind"
    RUST_VARIANT_ENV := RUSTC_BOOTSTRAP=1
  endif
else ifeq ($(RUST_VARIANT), release)
  RUST_VARIANT_CARGO_FLAGS = -Zbuild-std=std,panic_abort -Zbuild-std-features="$(RUST_STD_FEATURES)"
  # lets any cargo accept -Zbuild-std
  RUST_VARIANT_ENV := RUSTC_BOOTSTRAP=1
  # keep the host sysroot path out of std's panic locations; deferred, so that
  # rustc is only queried when a Rust component is built
  RUST_VARIANT_RUSTFLAGS = --remap-path-prefix=$(shell MAKEFLAGS= $(RUSTC) --print sysroot)/lib/rustlib/src/rust/=
else
  $(error RUST_VARIANT must be "checked" or "release", not "$(RUST_VARIANT)")
endif

# shared by all components of a target and variant, so std is built only once
RUST_BUILD_DIR = $(PREFIX_BUILD)/rust-build/$(RUST_VARIANT)
RUST_PROFILE_DIR = $(patsubst dev,debug,$(RUST_PROFILE))

# RUST_TARGET (from target/<arch>.mk) as it appears in CARGO_TARGET_<triple>_* variables
RUST_TARGET_ENV = $(subst -,_,$(call uppercase,$(RUST_TARGET)))

# rustc links through $(CC) as the C link rule does, CFLAGS included (they pick
# the multilib, e.g. armv7a's -mthumb). Unquoted, as cargo does not unquote
# RUSTFLAGS; RUST_LDFLAGS_FILTER (target/<arch>.mk) drops what the linker rejects.
RUST_LINK_ARGS = $(subst ",,$(filter-out $(SYSROOT_OPTS),$(CFLAGS)) $(filter-out $(RUST_LDFLAGS_FILTER),$(LDFLAGS)) $(SYSROOT_OPTS))

# RUST_TARGET_RUSTFLAGS (target/<arch>.mk) covers what the target spec cannot
RUSTFLAGS_TARGET = -L native=$(PREFIX_A) $(patsubst %,-C link-arg=%,$(RUST_LINK_ARGS)) $(RUST_TARGET_RUSTFLAGS) $(RUST_VARIANT_RUSTFLAGS) $(USER_RUSTFLAGS)

# runs target binaries for cargo test/run, e.g. phoenix-rtos-tests/cargo-runner.py
RUST_RUNNER ?=

RUST_CARGO_VARS = \
	RUSTC="$(RUSTC)" \
	$(RUST_VARIANT_ENV) \
	CARGO_BUILD_TARGET="$(RUST_TARGET)" \
	CARGO_TARGET_$(RUST_TARGET_ENV)_LINKER="$(CC)" \
	$(if $(RUST_RUNNER),CARGO_TARGET_$(RUST_TARGET_ENV)_RUNNER="$(RUST_RUNNER)" RUST_RUNNER_STRIP="$(STRIP)",) \
	TARGET="$(TARGET)"

RUST_TARGET_CC = $(subst -,_,$(RUST_TARGET))
RUST_EXPORT_CARGO_VARS = \
	$(RUST_CARGO_VARS) \
	CARGO="$(CARGO)" \
	CARGO_TARGET_$(RUST_TARGET_ENV)_RUSTFLAGS="$(RUSTFLAGS_TARGET)" \
	CRATE_CC_NO_DEFAULTS=1 \
	CC_$(RUST_TARGET_CC)="$(CC)" \
	AR_$(RUST_TARGET_CC)="$(AR)" \
	CFLAGS_$(RUST_TARGET_CC)="$(subst ",,$(EXPORT_CFLAGS))"

# vim:expandtab:ts=2:sw=2
