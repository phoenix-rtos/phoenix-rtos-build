# Makefile rules for a unit-test binary - a thin wrapper over binary.mk
#
# Everything binary.mk accepts (LOCAL_SRCS, LIBS, DEP_LIBS, LOCAL_CFLAGS, ...)
# works here as well, but the component is registered in TEST_COMPONENTS instead
# of ALL_COMPONENTS - so adding a test next to the code it covers does not change
# what the repository builds by default - and gains a "<NAME>-run" goal.
#
# A unit test is expected to be self-contained: no arguments, no fixtures to
# prepare, exit status is the verdict.

TEST_NAME := $(NAME)

include $(binary.mk)  # NOTE: resets NAME, LOCAL_* and friends

# a test is not a part of the product - keep it out of the all/install/clean
# goals, which repositories derive from ALL_COMPONENTS
ALL_COMPONENTS := $(filter-out $(TEST_NAME),$(ALL_COMPONENTS))
TEST_COMPONENTS += $(TEST_NAME)

.PHONY: $(TEST_NAME)-run

# necessary for TEST_NAME to be correctly set in the recipes below
$(TEST_NAME)-run: TEST_NAME := $(TEST_NAME)

ifeq ($(TARGET_FAMILY), host)
# the unstripped binary - a sanitizer or assert backtrace without symbols is not worth much
$(TEST_NAME)-run: $(TEST_NAME)
	@echo "RUN $(TEST_NAME)"
	$(SIL)$(PREFIX_PROG)$(TEST_NAME)
else
# a cross-built test is installed into the rootfs and executed on the device by
# the test runner, see phoenix-rtos-tests
$(TEST_NAME)-run:
	@echo "$(TEST_NAME): cross-built, cannot be run on the build host" >&2
	@exit 1
endif

# cleaning vars to avoid strange errors (binary.mk cleans up the rest)
TEST_NAME :=

# vim:expandtab:ts=2:sw=2
