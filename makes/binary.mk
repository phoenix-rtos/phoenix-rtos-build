# Makefile rules for compiling and linking binary file
# supported external variables:
# - NAME - component/target binary name
# - LOCAL_SRCS - list of source files relative to current makefile
# - SRCS       - list of source files relative to project root
# - LOCAL_HEADERS     - headers to be installed (relative to current makefile)
# - LOCAL_HEADERS_DIR - headers tree be installed (relative to current makefile) - default "include"
# - HEADERS           - headers to be installed (relative to project root)
# - DEP_LIBS - static libraries from current repo needed to be compiled/installed before this component (shortcut for putting something in LIBS and DEPS)
# - DEPS - list of components from current repo to be completed before starting this one
# - LIBS - names of the static libs to link the binary against (without .a suffix)
# - LOCAL_CFLAGS  - additional CFLAGS for current component compilation
# - LOCAL_CXXFLAGS - additional CXXFLAGS for current component compilation
# - LOCAL_LDFLAGS - additional LDFLAGS for current component linking
# - LOCAL_LDLIBS  - additional LDLIBS for current component linking
# - LOCAL_INSTALL_PATH - custom rootfs dir for the binary to be installed (if not provided - DEFAULT_INSTALL_PATH)

# Global variables (not reset by this script):
# - ROOTFS_INSTALL_UNSTRIPPED - if non-empty - install binaries into rootfs from PREFIX_PROG (instead of _STRIPPED)


# directory with current Makefile - relative to the repository root
# filter-out all Makefiles outside of TOPDIR
# WARNING: LOCAL_DIR computation would fail if any Makefile include would be done before including this file
# if necessary set LOCAL_DIR := $(call my-dir) at the beginning of the Makefile
ifeq ($(origin LOCAL_DIR), undefined)
  CLIENT_MAKES := $(filter $(TOPDIR)/%,$(abspath $(MAKEFILE_LIST)))
  LOCAL_DIR := $(patsubst $(TOPDIR)/%,%,$(dir $(lastword $(CLIENT_MAKES))))
endif

# external headers - by default "include" dir - to disable functionality set "LOCAL_HEADERS_DIR := nothing"
LOCAL_HEADERS_DIR ?= include
ABS_HEADERS_DIR := $(abspath ./$(LOCAL_DIR)/$(LOCAL_HEADERS_DIR))

SRCS += $(addprefix $(LOCAL_DIR), $(LOCAL_SRCS))
HEADERS += $(addprefix $(LOCAL_DIR), $(LOCAL_HEADERS))

# removing all files with unsupported extensions
SRCS := $(filter $(LANGUAGE_EXTENSIONS), $(SRCS))

# linking prerequisites
OBJS.$(NAME) := $(patsubst %,$(PREFIX_O)%.o,$(basename $(SRCS)))
RESOLVED_LIBS := $(patsubst %,$(PREFIX_A)%.a, $(DEP_LIBS))
RESOLVED_LIBS += $(patsubst %,$(PREFIX_A)%.a, $(LIBS))

# compilation prerequisites - component order-only dependency
DEPS += $(DEP_LIBS)
$(OBJS.$(NAME)): | $(DEPS)

# potentially custom CFLAGS/CXXFLAGS/LDFLAGS for compilation and linking
# add ABS_HEADERS_DIR to CFLAGS/CXXFLAGS as a first -I path to build always using local headers instead of installed ones
$(OBJS.$(NAME)): CFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CFLAGS) $(LOCAL_CFLAGS)
$(OBJS.$(NAME)): CXXFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CXXFLAGS) $(LOCAL_CXXFLAGS)
$(PREFIX_PROG)$(NAME): LDFLAGS:=$(LDFLAGS) $(LOCAL_LDFLAGS)
$(PREFIX_PROG)$(NAME): LDLIBS:=$(LOCAL_LDLIBS) $(LDLIBS)

# dynamically generated dependencies (file-to-file dependencies)
DEPS.$(NAME) := $(patsubst %,$(PREFIX_O)%.d,$(SRCS))
-include $(DEPS.$(NAME))

# rule for installing headers
INSTALLED_HEADERS.$(NAME) := $(patsubst $(LOCAL_DIR)%.h, $(PREFIX_H)%.h, $(HEADERS))

# external headers dir support (install whole subtree)
INSTALLED_HEADERS_TREE.$(NAME) := $(patsubst $(ABS_HEADERS_DIR)/%,$(PREFIX_H)%,$(shell find $(ABS_HEADERS_DIR) -type f -name '*.h' 2>/dev/null))

ifneq ($(filter-out $(PREFIX_H)%, $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME))),)
  $(error $(NAME): Installing headers outside of PREFIX_H, check Your makefile: $(INSTALLED_HEADERS.$(NAME) $(INSTALLED_HEADERS_TREE.$(NAME))))
endif

$(INSTALLED_HEADERS.$(NAME)): $(PREFIX_H)%.h: $(LOCAL_DIR)%.h
	$(HEADER)

$(INSTALLED_HEADERS_TREE.$(NAME)): $(PREFIX_H)%.h: $(ABS_HEADERS_DIR)/%.h
	$(HEADER)

# rule for linking binary
# NOTE: if applied globally, we could remove the $(LINK) variable and put explicit commands here
# NOTE: disabled $(PHOENIXLIB) direct dependency until it can be removed from $(LIBS)
$(PREFIX_PROG)$(NAME): $(OBJS.$(NAME)) $(RESOLVED_LIBS) # $(PHOENIXLIB)
	$(LINK)

# create component phony targets
.PHONY: $(NAME) $(NAME)-headers $(NAME)-clean $(NAME)-install

$(NAME)-headers: $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME))

$(NAME): $(NAME)-headers $(PREFIX_PROG_STRIPPED)$(NAME)

$(NAME)-clean:
	@echo "cleaning $(NAME)"
	@rm -rf $(OBJS.$(NAME)) $(DEPS.$(NAME)) $(PREFIX_PROG)$(NAME) $(PREFIX_PROG_STRIPPED)$(NAME) $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME))

# install into the root filesystem
LOCAL_INSTALL_PATH := $(or $(LOCAL_INSTALL_PATH),$(DEFAULT_INSTALL_PATH))

# add option to install unstripped binaries
ifeq ($(ROOTFS_INSTALL_UNSTRIPPED),)
  ROOTFS_BIN_SRC := $(PREFIX_PROG_STRIPPED)$(NAME)
else
  ROOTFS_BIN_SRC := $(PREFIX_PROG)$(NAME)
endif

$(NAME)-install: $(NAME) $(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME)
$(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME): $(ROOTFS_BIN_SRC)
	$(INSTALL_FS)

# necessary for NAME variable to be correctly set in recepies
$(NAME) $(NAME)-clean: NAME:=$(NAME)

ALL_COMPONENTS += $(NAME)

# cleaning vars to avoid strange errors
NAME :=
LOCAL_SRCS :=
undefine LOCAL_DIR # need to treat LOCAL_DIR="" as a valid (set-extenally) value
LOCAL_HEADERS :=
undefine LOCAL_HEADERS_DIR # undefine needed for default value to work in next component
DEP_LIBS :=
DEPS :=
SRCS :=
HEADERS :=
LIBS :=
LOCAL_CFLAGS :=
LOCAL_CXXFLAGS :=
LOCAL_LDFLAGS :=
LOCAL_LDLIBS :=
LOCAL_INSTALL_PATH :=
