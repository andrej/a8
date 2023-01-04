ARCH ?= $(shell uname -m)

ARCH_DIR     ?= arch
SOURCE_DIRS  ?= src $(ARCH_DIR)/$(ARCH)/src
TESTS_DIR    ?= tests
BUILD_DIR    ?= build
INCLUDE_DIRS ?= include $(ARCH_DIR)/$(ARCH)/include ../dependencies/libconfig-install/include ..
LIB_DIRS     ?= ../dependencies/libconfig-install/lib

CC      := gcc
CFLAGS  := -g -fpic $(INCLUDE_DIRS:%=-I%) \
           -fvisibility=hidden \
           -O2 -flto \
	   -fno-omit-frame-pointer
LDFLAGS := -g -shared $(LIB_DIRS:%=-L%) $(LIB_DIRS:%=-Wl,-rpath,%) \
           -fvisibility=hidden \
           -flto
LDLIBS  := -lconfig

C_SOURCES := $(shell find $(SOURCE_DIRS) -maxdepth 1 -name \*.c)
S_SOURCES := $(shell find $(SOURCE_DIRS) -maxdepth 1 -name \*.S)
C_OBJECTS := $(C_SOURCES:%.c=$(BUILD_DIR)/%.o)
S_OBJECTS := $(S_SOURCES:%.S=$(BUILD_DIR)/%.o)
DEPS      := $(C_OBJECTS:%.o=%.d)

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
all: $(BUILD_DIR)/libmonmod.so

$(BUILD_DIR)/%.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

$(BUILD_DIR)/%.o: %.c  # This rule also builds test objects
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD_DIR)/libmonmod.so: $(C_OBJECTS) $(S_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

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

-include $(DEPS)
-include $(TEST_DEPS)

