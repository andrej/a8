#ifndef MOCKS_H
#define MOCKS_H
/**
 * Contains some data types and definitions that our kernel-module tests need
 * but that we can't include directly. Tests should be simple enough to
 * not deeply depend on these structures; we just need them so we can pass
 * something useful to the linked kernel module object functions which
 * expect them. 
 * 
 * NOTE: mocking of kernel functions does not currently work in x86_64,
 * leading to a bunch of failed tests (Segmentation faults). Test on ARM64.
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

struct sysfs_ops {};

struct kobject { 
	const char *name;
	void *a, *b; /* struct list_head { struct list_head *next, *prev }*/
	struct kobject *parent;
	void *c; /* struct kset *kset */
	void *d; /* struct kobj_type *ktype */
	void *e; /* struct kernfs_node *sd */
	int f; /* struct kref { atomic_t( == struct with an int) refcount }*/
	unsigned int g:1, h:1, i:1, j:1, k:1;
};

struct kobj_attribute { struct kobject *kobj; const char *name; };

struct attribute { const char *name; umode_t mode; };
struct attribute_group { const char *name; struct attribute **attrs; };

struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
	/*const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);*/
};

extern struct sysfs_ops kobj_sysfs_ops;

struct tracepoint {
	const char *name;
	int key;
	void (*regfunc)(void);
	void (*unregfunc)(void);
	void *funcs;
};

#endif