CC := gcc
CFLAGS := -g
BUILD_DIR := ./build

all: $(BUILD_DIR)/read $(BUILD_DIR)/getcwd $(BUILD_DIR)/sched_yield

$(BUILD_DIR)/read: read.c build_config.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/getcwd: getcwd.c build_config.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/sched_yield: sched_yield.c build_config.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)