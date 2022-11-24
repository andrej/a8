ifdef TESTS_DIR
	ifdef TESTS_OBJS
		$(error TESTS_OBJS and TESTS_DIR may not be specified together)
	endif
	TEST_OBJS := $(shell find $(TESTS_DIR) -name \*.o)
endif

ifndef TEST_OBJS
$(error You must specify a directory of compiled test objects to link the test \
        suite with in TESTS_DIR or a list of objects as TEST_OBJS)
endif

SUITE_DIR ?= $(CURDIR)
BUILD_DIR ?= $(SUITE_DIR)/build

CC      ?= gcc
CFLAGS  += -g -pthread -I$(SUITE_DIR) 
LDFLAGS += -g -pthread -T$(SUITE_DIR)/main.lds 
LDLIBS  += 

SUITE_SRCS = $(shell find $(SUITE_DIR) -maxdepth 1 -name \*.c)
SUITE_OBJS = $(SUITE_SRCS:$(SUITE_DIR)/%.c=$(BUILD_DIR)/suite/%.o)
SUITE_DEPS = $(SUITE_OBJS:%.o=%.d)

.PHONY: all
all: $(BUILD_DIR)/test

$(BUILD_DIR)/test: $(SUITE_OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/suite/%.o: $(SUITE_DIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: test
test: $(BUILD_DIR)/test
	$(BUILD_DIR)/build/test

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
