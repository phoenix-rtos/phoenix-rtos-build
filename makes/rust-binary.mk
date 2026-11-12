# Makefile rules for building and installing a Rust binary with cargo
#
# supported external variables:
# - NAME - component name; also the name of the installed binary
# - LOCAL_RUST_BIN  - cargo `--bin` target to build (default: NAME)
# - LOCAL_MANIFEST  - Cargo.toml relative to the current makefile (default: Cargo.toml)
# - LOCAL_RUSTFLAGS - additional RUSTFLAGS for this component
# - LOCAL_CARGO_FLAGS - additional cargo arguments, e.g. --features foo
# - LOCAL_INSTALL_PATH - custom rootfs dir for the binary (if not provided - DEFAULT_INSTALL_PATH)
# - DEP_LIBS - static libraries from the current repo to build before this component
# - DEPS     - components from the current repo to complete before this one
# - LIBS     - names of static libs to link against (without .a suffix)
#
# Toolchain and build settings: makes/setup-rust.mk. The crate's tests: makes/rust-cargo.mk.
#
# cargo runs on every make invocation; the binary is copied to PREFIX_PROG only if it changed.

LOCAL_RUST_BIN ?= $(NAME)

include $(MAKES_PATH)/rust-cargo.mk

RUST_BIN.$(NAME) := $(LOCAL_RUST_BIN)
CARGO_OUT.$(NAME) := $(CARGO_DIR.$(NAME))/$(RUST_TARGET)/$(RUST_PROFILE_DIR)/$(LOCAL_RUST_BIN)

.PHONY: $(NAME) $(NAME)-cargo $(NAME)-clean $(NAME)-install

$(NAME)-cargo: | $(DEPS)
	@printf "CARGO %-22s\n" "$(NAME)"
	$(CHECK_RUST_ENV)
	$(NOTE_STD_BUILD)
	+$(SIL)$(CARGO_ENV.$(NAME)) $(CARGO) build $(CARGO_ARGS.$(NAME)) --bin "$(RUST_BIN.$(NAME))"

$(PREFIX_PROG)$(NAME): $(NAME)-cargo
	@mkdir -p $(@D)
	$(SIL)if ! cmp -s "$(CARGO_OUT.$(NAME))" "$@"; then \
		printf "LD  %-24s\n" "$(@F)"; \
		cp -p "$(CARGO_OUT.$(NAME))" "$@"; \
	fi

$(NAME): $(PREFIX_PROG_STRIPPED)$(NAME)

$(NAME)-clean:
	@echo "cleaning $(NAME)"
	@rm -rf $(CARGO_DIR.$(NAME)) $(PREFIX_PROG)$(NAME) $(PREFIX_PROG_STRIPPED)$(NAME)

# install into the root filesystem
LOCAL_INSTALL_PATH := $(or $(LOCAL_INSTALL_PATH),$(DEFAULT_INSTALL_PATH))

ifeq ($(ROOTFS_INSTALL_UNSTRIPPED),)
  ROOTFS_BIN_SRC := $(PREFIX_PROG_STRIPPED)$(NAME)
else
  ROOTFS_BIN_SRC := $(PREFIX_PROG)$(NAME)
endif

$(NAME)-install: $(NAME) $(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME)
$(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME): $(ROOTFS_BIN_SRC)
	$(INSTALL_FS)

# necessary for NAME to be correctly set in the recipes
$(NAME) $(NAME)-cargo $(NAME)-clean: NAME:=$(NAME)

ifeq ($(RUST_ENABLE), y)
  ALL_COMPONENTS += $(NAME)
else ifneq ($(filter all install,$(or $(MAKECMDGOALS),$(.DEFAULT_GOAL))),)
  $(info $(NAME): Rust component skipped, build with RUST_ENABLE=y)
endif
RUST_COMPONENTS += $(NAME)

# cleaning vars to avoid strange errors
NAME :=
undefine LOCAL_DIR
undefine LOCAL_MANIFEST
undefine LOCAL_RUST_BIN
LOCAL_RUSTFLAGS :=
LOCAL_CARGO_FLAGS :=
LOCAL_INSTALL_PATH :=
DEP_LIBS :=
DEPS :=
LIBS :=

# vim:expandtab:ts=2:sw=2
