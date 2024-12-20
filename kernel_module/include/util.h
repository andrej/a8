#ifndef UTIL_H
#define UTIL_H

#ifndef TEST_H
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/kernel.h>  // kstrtoint (linux/kstrtox.h in newer kernels)
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#endif

// access_ok signature changed with 
// commit 96d4f267e40f9509e8a66e2b39e8b95655617693
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define compat_access_ok(type, addr, size) access_ok(addr, size)
#else
#define compat_access_ok(type, addr, size) access_ok(type, addr, size)
#endif

#include "build_config.h"
#include "xxhash.h"

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

static inline int compare_user_region(const void __user *user_buffer,
                                      const void *kernel_buffer,
                                      const size_t len)
{
	//const u64 *user_longs = (const u64 *)user_buffer;
	const u64 user_longs[len];
	const u64 *kernel_longs = (const u64 *)kernel_buffer;
	const size_t u64_len = len/sizeof(u64);
	size_t i = 0;
	size_t s = 0;
	u64 v = 0;
	if(!compat_access_ok(VERIFY_READ, user_buffer, len)) {
		return 0;
	}
	if(0 != (s = copy_from_user((void*)user_longs, user_buffer, len))) {
		printk(KERN_WARNING "monmod: %lu bytes not copied in "
		       "compare_user_region", s);
	}
	for(; i < u64_len; i++) {
		get_user(v, user_longs + i);
		if(user_longs[i] != kernel_longs[i]) {
			return 1;
		}
	}
	return 0;
	/* Above implementation seems to be slightly faster than:
	   return memcmp(user_buffer, kernel_buffer, len); */
}

static inline unsigned long sdbm_hash(const unsigned char *buf, size_t len)
{
	const size_t u64_len = len/sizeof(u64);
	unsigned long hash = 0;
	size_t i = 0;
	size_t s = 0;
	const unsigned char buf_cpy[len];
	if(0 != (s = copy_from_user((void*)buf_cpy, buf, len))) {
		printk(KERN_WARNING "monmod: %lu bytes not copied in sdbm_hash", s);
	}
	for(; i < u64_len; i++) {
		u64 c = ((u64 *)buf_cpy)[i];
		//hash = c + (hash << 6) + (hash << 16) - hash;
		hash += c;
	}
	return hash;
}

static inline u64 hash_user_region(void __user const *start_addr, size_t len)
{
#if MONMOD_USE_XXH
	const u64 seed = 0;
#endif
	if(!compat_access_ok(VERIFY_READ, start_addr, len)) {
		return 0;
	}
#if MONMOD_USE_XXH
	return xxh32(start_addr, len, seed);
#else
	return sdbm_hash(start_addr, len);
#endif
}

#endif