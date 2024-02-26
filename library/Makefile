ARCH ?= $(shell uname -m)

ARCH_DIR     ?= arch
SOURCE_DIRS  ?= src $(ARCH_DIR)/$(ARCH)/src
TESTS_DIR    ?= tests
BUILD_DIR    ?= build
INCLUDE_DIRS ?= include \
                $(ARCH_DIR)/$(ARCH)/include \
                ../dependencies/libconfig-install/include \
                ../dependencies/criu-install/include \
                ..
LIB_DIRS     ?= ../dependencies/criu-install/lib/$(ARCH)-linux-gnu
LIBCONFIG_OBJECTS_DIR ?= ../dependencies/libconfig-1.7.3/lib/.libs
VMA_SERVER_DIR ?= vma-server

LIBVMA_PATH?=$(shell realpath $(shell gcc --print-file-name=libvma.so))

CC      := gcc
CFLAGS  := -g -fpic $(INCLUDE_DIRS:%=-I%) \
           -fvisibility=hidden \
           -fno-omit-frame-pointer \
		   '-DLIBVMA_PATH="${LIBVMA_PATH}"'
ifdef opt
CFLAGS  += -O3 -flto 
endif
# Linking with -pthread is required for the POSIX semaphores used for
# checkpointing
LDFLAGS := -g -shared $(LIB_DIRS:%=-L%) \
           -fvisibility=hidden -Tmain.lds \
	   -pthread 
ifdef opt
LDFLAGS += -O3 -flto
endif
LDLIBS  := -lrt -ldl -lcriu

C_SOURCES := $(shell find $(SOURCE_DIRS) -maxdepth 1 -name \*.c)
S_SOURCES := $(shell find $(SOURCE_DIRS) -maxdepth 1 -name \*.S)
ALL_C_OBJECTS := $(C_SOURCES:%.c=$(BUILD_DIR)/%.o)
ALL_S_OBJECTS := $(S_SOURCES:%.S=$(BUILD_DIR)/%.o)
DEPS      := $(ALL_C_OBJECTS:%.o=%.d)

# Objects for vsyscall_override.so
VSYSCALL_OVERRIDE_OBJECTS := $(BUILD_DIR)/src/vsyscall_override.o

# Objects for libmonmod.so
LIBCONFIG_OBJECTS := $(shell find $(LIBCONFIG_OBJECTS_DIR) -maxdepth 1 -name libconfig_la-\*.o)
C_OBJECTS := $(filter-out $(VSYSCALL_OVERRIDE_OBJECTS) \
                          $(BUILD_DIR)/vma-server/%,\
                          $(ALL_C_OBJECTS))
S_OBJECTS := $(ALL_S_OBJECTS)

TEST_SUITE_DIR := ../test_suite
TEST_SOURCES   := $(shell find $(TESTS_DIR) -maxdepth 1 -name \*.c)
TEST_OBJECTS   := $(TEST_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_DEP_OBJS  := $(filter-out $(SOURCE_DIRS:%=$(BUILD_DIR)/%/main.o) \
                               $(SOURCE_DIRS:%=$(BUILD_DIR)/%/init.o) \
                               $(SOURCE_DIRS:%=$(BUILD_DIR)/%/vsyscall_override.o),\
                               $(C_OBJECTS))
TEST_DEPS      := $(TEST_OBJECTS:%.o=%.d)
TEST_LDFLAGS   := 
TEST_LDLIBS    := ../dependencies/libconfig-install/lib/libconfig.a

.PHONY: all
all: $(BUILD_DIR)/libmonmod.so $(BUILD_DIR)/vsyscall_override.so \
     $(BUILD_DIR)/vma-server 

$(BUILD_DIR)/%.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

$(BUILD_DIR)/%.o: %.c  # This rule also builds test objects
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD_DIR)/libmonmod.so: $(C_OBJECTS) $(S_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBCONFIG_OBJECTS) $(LDLIBS) -Wl,--version-script=link.version 

$(BUILD_DIR)/vsyscall_override.so: $(VSYSCALL_OVERRIDE_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: $(BUILD_DIR)/vma-server
$(BUILD_DIR)/vma-server: 
	make -f $(VMA_SERVER_DIR)/Makefile	\
		CC="$(CC)" \
		BUILD_DIR="$(BUILD_DIR)" \
		INCLUDE_DIRS="$(INCLUDE_DIRS)"

.PHONY: tests
tests: $(TEST_OBJECTS) $(TEST_DEP_OBJS)
	make -f $(TEST_SUITE_DIR)/Makefile \
		SUITE_DIR=$(TEST_SUITE_DIR) \
		TEST_OBJS="$(TEST_OBJECTS) $(TEST_DEP_OBJS)" \
		BUILD_DIR=$(BUILD_DIR)/$(TESTS_DIR) \
		LDLIBS="$(TEST_LDLIBS)"


.PHONY: runtests
runtests: tests
	./$(BUILD_DIR)/$(TESTS_DIR)/test


.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: install
install: $(BUILD_DIR)/libmonmod.so
	cp $^ /usr/lib/libmonmod.so
	cp ../dependencies/libconfig-install/lib/libconfig.so.11 /usr/lib
	chmod u+s /usr/lib/libmonmod.so  # Permission needed for libVMA execution
	chmod u+s /usr/lib/libconfig.so.11
# TODO: Add library for CRIU checkpointing in install target 

.PHONY: uninstall
uninstall:
	rm /usr/lib/libmonmod.so

-include $(DEPS)
-include $(TEST_DEPS)
