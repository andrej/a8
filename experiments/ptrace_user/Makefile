CC := gcc
CFLAGS := -ggdb
SRCS := $(shell find . -maxdepth 1 -name \*.c)
TARGET := main

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm main