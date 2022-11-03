#ifndef UTIL_H
#define UTIL_H

#ifndef TEST_H
#include <linux/printk.h>
#include <linux/kernel.h>  // kstrtoint (linux/kstrtox.h in newer kernels)
#include <linux/string.h>
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
		printk(KERN_WARNING "lkm-fasttrace: " #x " failed\n"); \
	 	except; \
	} \
})

#define DELETE(x)  ({ \
	if(NULL != (x)) { \
		free((x)); \
		(x) = NULL; \
	} \
})

size_t line_length(const char *buf, size_t count);
ssize_t next_int_line(const char *buf, size_t count, int *res);

#endif