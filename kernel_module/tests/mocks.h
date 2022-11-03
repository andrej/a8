#ifndef MOCKS_H
#define MOCKS_H
/**
 * Contains some data types and definitions that our kernel-module tests need
 * but that we can't include directly. Tests should be simple enough to
 * not deeply depend on these structures; we just need them so we can pass
 * something useful to the linked kernel module object functions which
 * expect them. 
 */

#include <stdlib.h> // NULL 
#include <stdint.h>  // uint64_t etc
#include <stdio.h> // sscanf etc
#include <errno.h> // EINVAL etc
#include <sys/signal.h> // SIGSEV etc
#include <sys/types.h>   // for user-space types etc
#include <asm/unistd.h> // __NR_syscalls

#define KERN_INFO "KERN_INFO"
#define KERN_WARNING "KERN_WARNING"

#define PAGE_SIZE 4096

typedef uint64_t u64;

typedef unsigned short umode_t;

struct kobject { const char *name; struct kobject *parent; };

struct kobj_attribute { struct kobject *kobj; const char *name; };

struct attribute { const char *name; umode_t mode; };
struct attribute_group { const char *name; struct attribute **attrs; };

struct tracepoint {
	const char *name;
	int key;
	void (*regfunc)(void);
	void (*unregfunc)(void);
	void *funcs;
};

#endif