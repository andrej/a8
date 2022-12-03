#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "build_config.h"

#if VERBOSITY > 0
#define WARN(msg) { \
	WARNF(msg "%s", ""); \
}
#define WARNF(msg, ...) { \
	fprintf(stderr, __FILE__ ": %d: " msg, __LINE__, __VA_ARGS__); \
}
#else
#define WARN(...)
#define WARNF(x)
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

#endif