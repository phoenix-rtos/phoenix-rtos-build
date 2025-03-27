# Makefile rules for compiling and linking dynamically linked binary file
# supported external variables, besides those stated in binary.mk:
# - DEP_LIBS_SHARED - shared libraries from current repo needed to be compiled/installed before this component (shortcut for putting something in LIBS and DEPS)
# - LIBS_SHARED - names of the shared libs to link the binary against (without .so suffix)

ifeq (${HAVE_SHLIB},n)
	$(warning "binary-dyn.mk called on target not supporting dynamic linking!")
endif

RESOLVED_LIBS_SHARED := $(patsubst lib%,-l%, $(DEP_LIBS_SHARED) $(LIBS_SHARED))

DEPS += $(DEP_LIBS_SHARED)

# Add shared libraries directory search path
LD_FLAGS_DYN := -L$(PREFIX_SO)

LOCAL_LDFLAGS += $(LD_FLAGS_DYN)
LOCAL_LDLIBS += $(RESOLVED_LIBS_SHARED)

DYNAMIC_BINARY := y

include $(binary.mk)

DEP_LIBS_SHARED :=
LIBS_SHARED :=
