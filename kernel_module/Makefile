# There are two main targets (besides clean) in this Makefile: one to build the
# kernel module, and one to build the tests. The kernel module build
# configuration is mainly in the Kbuild file; if additional object file targets
# are to be added, add them there to the monmod-y variable.
#
# The kernel module is built with the Make-based Linux Kbuild. Some trickery is
# required to make Kbuild build in a seperate build directory: This Makefile
# creates the build directory, copies an empty Makefile into it so `make` can
# be called inside it, and then invokes Kbuild, which will use the Kbuild
# file, from the build directory, but with the `src` directory modified to point
# to the root.
#
# The tests do *not* use Kbuild. They depend on the kernel module already being
# built. All kernel module object code to be tested will be copied (actually 
# linked) into the test_suite/dependencies directory. The test cases themselves 
# will be built with all Linux kernel headers in the include path, in 
# test_suite/tests. Then, everything is linked together as specified in 
# test_suite/Makefile.


# ############################################################################ #
# CONFIGURATION                                                                # 
# ############################################################################ #

ARCH           ?= $(shell uname -m)
ifeq ($(ARCH),aarch64)
	ARCH    := arm64
endif
KERNEL_RELEASE ?= $(shell uname -r)

BUILD_DIR      ?= $(PWD)/build
TEST_SRCS_DIR  ?= tests
TEST_SUITE_DIR ?= test_suite
TEST_CC        ?= gcc
TEST_CFLAGS    ?= \
    -I./include -I. -g \
#    -I/usr/src/linux-headers-$(KERNEL_RELEASE)/include \
#    -I/usr/src/linux-headers-$(KERNEL_RELEASE)/arch/$(ARCH)/include \
#    -I/usr/src/linux-headers-$(KERNEL_RELEASE)/arch/$(ARCH)/include/generated
TEST_DEPS_EXCLUDE ?= src/main.o arch/$(ARCH)/ptrace.o \
	arch/$(ARCH)/export_symbols.o


# ############################################################################ #
# VARIABLES                                                                    # 
# ############################################################################ #

# Make variables from within Kbuild available
src = BUILD_DIR
include ./Kbuild

TEST_SRCS      := $(shell find $(TEST_SRCS_DIR) -name \*.c)
TEST_OBJS      := $(TEST_SRCS:%.c=$(TEST_SUITE_DIR)/%.o)
TEST_DEP_OBJS  := $(patsubst %.o,$(TEST_SUITE_DIR)/dependencies/%.o,\
                    $(filter-out $(TEST_DEPS_EXCLUDE),$(monmod-y)))


# ############################################################################ #
# KERNEL MODULE TARGETS                                                        # 
# ############################################################################ #

# Invoke Kbuild in build directory, with refrences to sources in this directory
.PHONY: module
module: $(BUILD_DIR)/Makefile
	make -C /lib/modules/$(KERNEL_RELEASE)/build \
	     M=$(BUILD_DIR) src=$(PWD) modules

$(BUILD_DIR)/Makefile: 
	@mkdir -p $(@D)
	@mkdir -p $(@D)/src
	@mkdir -p $(@D)/arch/$(ARCH)
	touch $@

.PHONY: clean
clean: clean_tests
	make -C /lib/modules/$(KERNEL_RELEASE)/build \
	     M=$(BUILD_DIR) src=$(PWD) clean
	rm -rf "$(BUILD_DIR)"


# ############################################################################ #
# TEST TARGETS                                                                 # 
# ############################################################################ #

# Build tests without Kbuild
.PHONY: tests
tests: $(TEST_OBJS) $(TEST_DEP_OBJS)
	cd $(TEST_SUITE_DIR); make

$(TEST_SUITE_DIR)/tests/%.o: tests/%.c
	$(TEST_CC) $(TEST_CFLAGS) -o $@ -c $<

$(TEST_SUITE_DIR)/dependencies/%.o: $(BUILD_DIR)/%.o
	@mkdir -p $(@D)
	ln -s -t $(@D) $^ 

.PHONY: clean_tests
clean_tests: 
	rm -rf $(TEST_SUITE_DIR)/tests/*
	rm -rf $(TEST_SUITE_DIR)/dependencies/*
	cd $(TEST_SUITE_DIR); make clean

.PHONY: run_tests
run_tests:
	$(TEST_SUITE_DIR)/build/test
