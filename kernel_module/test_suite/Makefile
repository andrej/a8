KERNEL_RELEASE = $(shell uname -r)
ARCH   = $(shell uname -m)

CC     = gcc
CFLAGS += -g -O3 -I. 
LDFLAGS += -g -Tmain.lds 

BUILD_DIR = build
SRCS = $(shell find . -maxdepth 1 -name \*.c) 
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o) $(shell find tests -name \*.o) $(shell find dependencies -name \*.o)
DEPS = $(OBJS:%.o=%.d)

.PHONY: all
all: $(BUILD_DIR)/test

$(BUILD_DIR)/test: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: test
test: ./build/test
	./build/test

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
