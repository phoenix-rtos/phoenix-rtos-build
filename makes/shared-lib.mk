# Makefile rules for compiling a shared library
# supported external variables:
# - NAME - component/target binary name
# - LOCAL_SRCS - list of source files relative to current makefile
# - SRCS       - list of source files relative to project root
# - LOCAL_HEADERS     - headers to be installed (relative to current makefile)
# - LOCAL_HEADERS_DIR - headers tree be installed (relative to current makefile) - default "include"
# - HEADERS           - headers to be installed (relative to project root)
# - LOCAL_LDFLAGS - additional LDFLAGS for current component linking
#
# - DEPS - list of components from current repo to be completed before starting this one
# - DEP_LIBS_SHARED - shared libraries from current repo needed to be compiled/installed before this component (shortcut for putting something in LIBS and DEPS)
# - LIBS_SHARED - names of the shared libs to link the binary against (without .so suffix)
# - LOCAL_LDLIBS  - additional LDLIBS for current component linking
# - LOCAL_CFLAGS  - additional CFLAGS for current component compilation
# - LOCAL_CXXFLAGS  - additional CXXFLAGS for current component compilation
#
# - SONAME - library soname, defaults to $(NAME).so, to disable set to 'nothing'
# - LOCAL_VERSION_SCRIPT - version script relative to current makefile
#
# - LOCAL_INSTALL_PATH - custom rootfs dir for the shared library to be installed (if not provided - DEFAULT_INSTALL_PATH_SO)


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

# Add libs
RESOLVED_LIBS_SHARED := $(patsubst lib%,-l%, $(DEP_LIBS_SHARED) $(LIBS_SHARED))
LOCAL_LDLIBS += $(RESOLVED_LIBS_SHARED)

DEPS += $(DEP_LIBS_SHARED)

# compilation prerequisites - component order-only dependency
$(OBJS.$(NAME)): | $(DEPS)

# Shared lib flags
SHARED_LIB_LD_FLAGS := $(TARGET_PIC_FLAG) -shared -z text -L$(PREFIX_SO)

SONAME ?= $(NAME).so

ifneq ($(SONAME), nothing)
SHARED_LIB_LD_FLAGS += $(LDFLAGS_PREFIX)-soname,$(SONAME)
endif

ifneq ($(LOCAL_VERSION_SCRIPT),)
SHARED_LIB_LD_FLAGS += $(LDFLAGS_PREFIX)--version-script=$(LOCAL_DIR)/$(LOCAL_VERSION_SCRIPT)
endif

# potentially custom CFLAGS/CXXFLAGS/LDFLAGS for compilation and linking
# add ABS_HEADERS_DIR to CFLAGS/CXXFLAGS to build always using local headers instead of installed ones
$(OBJS.$(NAME)): CFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CFLAGS) $(LOCAL_CFLAGS) $(TARGET_PIC_FLAG)
$(OBJS.$(NAME)): CXXFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CXXFLAGS) $(LOCAL_CXXFLAGS) $(TARGET_PIC_FLAG)

$(PREFIX_SO)$(NAME).so: LDFLAGS:=$(LDFLAGS) $(SHARED_LIB_LD_FLAGS) $(LOCAL_LDFLAGS)
$(PREFIX_SO)$(NAME).so: LDLIBS:=$(LDLIBS) $(LOCAL_LDLIBS)

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

# rule for linking shared lib
$(PREFIX_SO)$(NAME).so: $(OBJS.$(NAME))
	$(LINK)

# create component phony targets
.PHONY: $(NAME) $(NAME)-headers $(NAME)-clean

$(NAME)-headers: $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME))

$(NAME): $(NAME)-headers $(PREFIX_SO)$(NAME).so

$(NAME)-clean:
	@echo "cleaning $(NAME)"
	@rm -rf $(OBJS.$(NAME)) $(DEPS.$(NAME)) $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME)) $(PREFIX_SO)$(NAME).so

# install into the root filesystem
LOCAL_INSTALL_PATH := $(or $(LOCAL_INSTALL_PATH),$(DEFAULT_INSTALL_PATH_SO))

$(NAME)-install: $(NAME) $(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME).so
$(PREFIX_ROOTFS)$(LOCAL_INSTALL_PATH)/$(NAME).so: $(PREFIX_SO)$(NAME).so
	$(INSTALL_FS)

# necessary for NAME variable to be correctly set in recipes
$(NAME) $(NAME)-clean: NAME:=$(NAME)

ALL_COMPONENTS += $(NAME)

# cleaning vars to avoid strange errors
NAME :=
LOCAL_SRCS :=
undefine LOCAL_DIR # need to treat LOCAL_DIR="" as a valid (set-extenally) value
LOCAL_HEADERS :=
undefine LOCAL_HEADERS_DIR # undefine needed for default value to work in next component
DEPS :=
SRCS :=
HEADERS :=
DEP_LIBS_SHARED :=
LIBS_SHARED :=
LOCAL_LDFLAGS :=
LOCAL_CFLAGS :=
LOCAL_CXXFLAGS :=
LOCAL_LDLIBS :=
undefine SONAME
LOCAL_VERSION_SCRIPT :=
undefine LOCAL_INSTALL_PATH

