#ifndef UTIL_H
#define UTIL_H

#ifndef TEST_H
#include <linux/printk.h>
#include <linux/kernel.h>  // kstrtoint (linux/kstrtox.h in newer kernels)
#include <linux/string.h>
#include <linux/ctype.h>
#endif

#include "build_config.h"

#define MONMOD_WARN(x) ({ \
	printk(KERN_WARNING " monmod: " #x); \
})

#define MONMOD_WARNF(x, ...) ({ \
	printk(KERN_WARNING " monmod: " #x "\n", __VA_ARGS__); \
})

#define TRY(x, except) ({ \
	if(0 != (x)) { \
		printk(KERN_WARNING "monmod: " #x " failed\n"); \
	 	except; \
	} \
})

#define DELETE(x)  ({ \
	if(NULL != (x)) { \
		free((x)); \
		(x) = NULL; \
	} \
})

#define BETWEEN(a, min, max) \
	(min <= (a) && (a) < max)

size_t line_length(const char *buf, size_t count);

/**
 * Returns -1 if any of the remaining input is invalid (contains characters
 * that are neither whitespace nor digits), or if a number cannot be parsed
 * because it is too large.
 * 
 * Returns 0 if the entire buffer has been consumed and there are no remaining
 * numbers (i.e. either buf is empty or consists only of whitespace).
 * 
 * Returns the positive number of consumed characters if res has been populated
 * with a parsed integer from the buffer input. 
 */
ssize_t next_int_line(const char *buf, size_t count, int *res);

#endif