CC := gcc
CFLAGS := -g -fpic -shared

vsyscall_override.so: vsyscall_override.c
	$(CC) $(CFLAGS) -o $@ $^