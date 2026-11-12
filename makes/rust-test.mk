# Makefile rules for the tests of a Rust crate without a binary of its own, e.g. a library
#
# supported external variables: NAME (the test is test-<NAME>), LOCAL_MANIFEST,
# LOCAL_RUSTFLAGS, LOCAL_CARGO_FLAGS, DEP_LIBS, DEPS, LIBS - as in rust-binary.mk

include $(MAKES_PATH)/rust-cargo.mk

# cleaning vars to avoid strange errors
NAME :=
undefine LOCAL_DIR
undefine LOCAL_MANIFEST
LOCAL_RUSTFLAGS :=
LOCAL_CARGO_FLAGS :=
DEP_LIBS :=
DEPS :=
LIBS :=

# vim:expandtab:ts=2:sw=2
