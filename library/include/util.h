#ifndef UTIL_H
#define UTIL_H

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <link.h>
#include <elf.h>

#include "build_config.h"
#include "syscall.h"
#include "custom_syscalls.h"


/* ************************************************************************** *
 * Macros                                                                     *
 * ************************************************************************** */

#define free_and_null(x) { \
	free(x); \
	x = NULL; \
}

#if VERBOSITY > 0

#define WARN(msg) { \
	WARNF(msg "%s", ""); \
}
#define WARNF(msg, ...) { \
	fprintf(stderr, __FILE__ ": %d: " msg, __LINE__, __VA_ARGS__); \
}

/* The SAFE_* log functions print to log_fd using a monmod_trusted_syscall,
   instead of stderr, which makes them suitable for use in syscall handlers,
   where stderr might be closed or pointing to something else. */
#define SAFE_LOGF_LEN(n, msg, ...) { \
	char log[n]; \
	int len = 0; \
	len = snprintf(log, sizeof(log), msg, __VA_ARGS__); \
	if(len >= sizeof(log)) { \
		log[sizeof(log)-1] = '\0'; \
	} \
	if(0 < len) { \
		monmod_trusted_syscall(__NR_write, monmod_log_fd, (long)log, \
		                       (long)len, 0, 0, 0); \
	} \
}
#define SAFE_LOGF(msg, ...) SAFE_LOGF_LEN(256, msg, __VA_ARGS__)
#define SAFE_LOG(msg) SAFE_LOGF(msg "%s", "")
#define SAFE_WARNF(msg, ...) SAFE_LOGF(__FILE__ ": %d: " msg, __LINE__, \
                                       __VA_ARGS__)
#define SAFE_WARN(msg) SAFE_WARNF(msg "%s", "")

#else
#define WARN(...)
#define WARNF(...)
#define SAFE_LOGF_LEN(...)
#define SAFE_LOGF(...)
#define SAFE_LOG(...)
#define SAFE_WARNF(...)
#define SAFE_WARN(...)
#endif

#define TRY_EXCEPT_F(x, rhs, except, print_func) { \
	const long ret_val = (long)(x); \
	if(ret_val rhs) { \
		print_func(#x " failed with return value %ld\n", ret_val); \
		except; \
	} \
}

#define TRY_EXCEPT(x, rhs, except) TRY_EXCEPT_F(x, rhs, except, WARNF)
#define NZ_TRY_EXCEPT(x, except) TRY_EXCEPT(x, != 0, except)
#define LZ_TRY_EXCEPT(x, except) TRY_EXCEPT(x, < 0, except)
#define Z_TRY_EXCEPT(x, except) TRY_EXCEPT(x, == 0, except)

#define SAFE_TRY_EXCEPT(x, rhs, except) TRY_EXCEPT_F(x, rhs, except, SAFE_WARNF)
#define SAFE_NZ_TRY_EXCEPT(x, except) SAFE_TRY_EXCEPT(x, != 0, except)
#define SAFE_LZ_TRY_EXCEPT(x, except) SAFE_TRY_EXCEPT(x, < 0, except)
#define SAFE_Z_TRY_EXCEPT(x, except) SAFE_TRY_EXCEPT(x, == 0, except)

#define NZ_TRY(x) NZ_TRY_EXCEPT(x, return 1)
#define LZ_TRY(x) LZ_TRY_EXCEPT(x, return 1)
#define Z_TRY(x) Z_TRY_EXCEPT(x, return 1)

#define SAFE_NZ_TRY(x) SAFE_NZ_TRY_EXCEPT(x, monmod_exit(1))
#define SAFE_LZ_TRY(x) SAFE_LZ_TRY_EXCEPT(x, monmod_exit(1))
#define SAFE_Z_TRY(x) SAFE_Z_TRY_EXCEPT(x, monmod_exit(1))


/* ************************************************************************** *
 * Global variables                                                           *
 * ************************************************************************** */

extern int monmod_log_fd;  // Initialized in monmod_library_init()
extern size_t monmod_page_size;


/* ************************************************************************** *
 * Miscellaneous functions                                                    *
 * ************************************************************************** */

static inline unsigned long sdbm_hash(size_t buf_len, unsigned char *buf) {
	unsigned long hash = 0;
	unsigned int c = 0;
	for(size_t i = 0; i < buf_len; i++) {
		c = buf[i];
		hash = c + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

/**
 * Safe alternative to malloc() that can be called from within system call
 * handlers. Since calloc() and malloc() are non-reentrant, we cannot safely
 * use them inside system call handlers; instead we use this, which simply
 * issues an anonymous mmap() call.
 */
void *safe_malloc(size_t size);
void safe_free(void *ptr, size_t size);

int find_mapped_region_bounds(void * const needle, 
                              void **start, size_t *len);

/**
 * Open a new global log file, truncating an existing file in case it already 
 * exists. Returns 0 on success. maj and min are identification numbers that 
 * are currently used as follows: maj is the ID used in the configuration 
 * file for the variant, and min is an ID that adds a digit for every spawned
 * child.
 */
int open_log_file(unsigned long maj, unsigned long min);

#endif