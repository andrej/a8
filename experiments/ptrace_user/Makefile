ARCH := $(shell uname -m)
CC := gcc
CFLAGS := -ggdb
SRCS := $(shell find . -maxdepth 1 -name \*.c)
ARCH_SRCS := $(shell find $(ARCH) -maxdepth 1 -name \*.c)
TARGET := main

# TODO track header file dependencies

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(TARGET): $(SRCS:%.c=%.o) $(ARCH_SRCS:%.c=%.o)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm $(ARCH)/*.o
	rm main