# Makefile rules for compiling and static library
# supported external variables:
# - NAME - component/target binary name
# - LOCAL_SRCS - list of source files relative to current makefile
# - SRCS       - list of source files relative to project root
# - LOCAL_HEADERS     - headers to be installed (relative to current makefile)
# - LOCAL_HEADERS_DIR - headers tree be installed (relative to current makefile) - default "include"
# - HEADERS           - headers to be installed (relative to project root)
#
# - DEPS - list of components from current repo to be completed before starting this one
#
# - LOCAL_CFLAGS  - additional CFLAGS for current component compilation
# - LOCAL_CXXFLAGS  - additional CXXFLAGS for current component compilation
#



# directory with current Makefile - relative to the repository root
# filter-out all Makefiles outside of TOPDIR
# WARNING: LOCAL_DIR computation would fail if any Makefile include would be done before including this file
# if necessary set LOCAL_DIR := $(call my-dir) at the beginning of the Makefile
ifeq ($(origin LOCAL_DIR), undefined)
  CLIENT_MAKES := $(filter $(TOPDIR)/%,$(abspath $(MAKEFILE_LIST)))
  LOCAL_DIR := $(patsubst $(TOPDIR)/%,%,$(dir $(lastword $(CLIENT_MAKES))))
endif

# binary.mk clears all variables it uses so we should expect that they are not set here. Leaving them set would
# influence next binary.mk call leading to unexpected errors
ifneq ($(DEP_LIB)$(LIBS)$(LOCAL_LDFLAGS)$(LOCAL_LDLIBS)$(LOCAL_INSTALL_PATH),)
  $(warning $(NAME): DEP_LIB=$(DEP_LIB))
  $(warning $(NAME): LIBS=$(LIBS))
  $(warning $(NAME): LOCAL_LDFLAGS=$(LOCAL_LDFLAGS))
  $(warning $(NAME): LOCAL_LDLIBS=$(LOCAL_LDLIBS))
  $(warning $(NAME): LOCAL_INSTALL_PATH=$(LOCAL_INSTALL_PATH))
  $(error $(NAME): static-lib.mk invoked with args reserved for binary.mk)
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

# compilation prerequisites - component order-only dependency
$(OBJS.$(NAME)): | $(DEPS)

# potentially custom CFLAGS/CXXFLAGS/LDFLAGS for compilation and linking
# add ABS_HEADERS_DIR to CFLAGS/CXXFLAGS to build always using local headers instead of installed ones
$(OBJS.$(NAME)): CFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CFLAGS) $(LOCAL_CFLAGS)
$(OBJS.$(NAME)): CXXFLAGS:=-I"$(ABS_HEADERS_DIR)" $(CXXFLAGS) $(LOCAL_CXXFLAGS)

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

# allow header-only components
LIBNAME :=
ifneq ($(strip $(SRCS)),)
  LIBNAME := $(PREFIX_A)$(NAME).a
endif

# rule for linking static lib
# NOTE: if applied globally, we could remove the $(ARCH) variable and put explicit commands here
$(PREFIX_A)$(NAME).a: $(OBJS.$(NAME))
	$(ARCH)

# create component phony targets
.PHONY: $(NAME) $(NAME)-headers $(NAME)-clean

$(NAME)-headers: $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME))

$(NAME): $(NAME)-headers $(LIBNAME)

$(NAME)-clean:
	@echo "cleaning $(NAME)"
	@rm -rf $(OBJS.$(NAME)) $(DEPS.$(NAME)) $(INSTALLED_HEADERS.$(NAME)) $(INSTALLED_HEADERS_TREE.$(NAME)) $(PREFIX_A)$(NAME).a

# no installation for static libs
$(NAME)-install: $(NAME) ;

# necessary for NAME variable to be correctly set in recepies
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
LOCAL_CFLAGS :=
LOCAL_CXXFLAGS :=
