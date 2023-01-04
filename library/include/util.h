#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include "build_config.h"
#include "syscall.h"

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
#else
#define WARN(...)
#define WARNF(...)
#endif

#define TRY_EXCEPT(x, rhs, except) { \
	const long ret_val = (long)(x); \
	if(ret_val rhs) { \
		WARNF(#x " failed with return value %ld: %s\n", ret_val, \
		strerror(errno)); \
		except; \
	} \
}
#define NZ_TRY_EXCEPT(x, except) TRY_EXCEPT(x, != 0, except)
#define LZ_TRY_EXCEPT(x, except) TRY_EXCEPT(x, < 0, except)
#define Z_TRY_EXCEPT(x, except) TRY_EXCEPT(x, == 0, except)

#define NZ_TRY(x) NZ_TRY_EXCEPT(x, return 1)
#define LZ_TRY(x) LZ_TRY_EXCEPT(x, return 1)
#define Z_TRY(x) Z_TRY_EXCEPT(x, return 1)

extern int log_fd;

#define SAFE_LOGF_LEN(n, log_fd, msg, ...) { \
	char log[n]; \
	int len = 0; \
	len = snprintf(log, sizeof(log), \
	              msg, __VA_ARGS__); \
	if(0 < len && len < sizeof(log)) { \
		monmod_trusted_syscall(__NR_write, log_fd, (long)log, \
		                       (long)len, 0, 0, 0); \
	} \
}

#define SAFE_LOGF(log_fd, msg, ...) SAFE_LOGF_LEN(128, log_fd, msg, __VA_ARGS__)

static inline unsigned long sdbm_hash(size_t buf_len, unsigned char *buf) {
	unsigned long hash = 0;
	unsigned int c = 0;
	for(size_t i = 0; i < buf_len; i++) {
		c = buf[i];
		hash = c + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

#endif