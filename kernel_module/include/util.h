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

u64 hash_user_region(void __user *start_addr, void __user *stop_addr);

static inline u64 sdbm_hash(size_t buf_len, unsigned char *buf) {
	size_t i = 0;
	u64 hash = 0;
	unsigned int c = 0;
	for(i = 0; i < buf_len; i++) {
		c = buf[i];
		hash = c + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

#endif