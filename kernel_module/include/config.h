#ifndef MONMOD_CONFIG_H
#define MONMOD_CONFIG_H

/**
 * The modmon configuration is exposed to user space through the sysfs
 * file system. This file contains the implementation thereof.
 * 
 * All settings are stored in a global struct, monmod_global_config, of type
 * struct monmod_config. This must be initialized with init_config() and freed
 * with free_config(). Initialization exports the settings to sysfs.
 */

#ifndef TEST_H
#include <linux/types.h> 
#include <linux/unistd.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#endif

#include "build_config.h"

/* ************************************************************************** *
 * Macros                                                                     *
 * ************************************************************************** */

#define MONMOD_BITS_PER_MASK 64
#define MONMOD_N_SYSCALL_MASKS ((__NR_syscalls + MONMOD_BITS_PER_MASK - 1) \
                                / MONMOD_BITS_PER_MASK)


/* ************************************************************************** *
 * Data Types & Global Variables                                              *
 * ************************************************************************** */

struct monmod_config {
	struct kobject *kobj;
	pid_t tracee_pid;
	pid_t tracer_pid;
	u64 syscall_masks[MONMOD_N_SYSCALL_MASKS];
};

extern struct monmod_config monmod_global_config;


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_config_init(void);
void monmod_config_free(void);

int monmod_syscall_is_active(u64 syscall_no);
int monmod_syscall_activate(u64 syscall_no);
int monmod_syscall_deactivate(u64 syscall_no);


/* ************************************************************************** *
 * Internals                                                                  *
 * (Exported in test header anyways so we can test them.)                     *
 * ************************************************************************** */

int _monmod_syscall_mask_index(u64 syscall_no);
int _monmod_syscall_mask_offset(u64 syscall_no);

ssize_t _monmod_config_pid_show(struct kobject *kobj, 
                                struct kobj_attribute *attr, 
                                char *buf);
ssize_t _monmod_config_pid_store(struct kobject *kobj, 
                                 struct kobj_attribute *attr, 
                                 const char *buf, size_t count);
ssize_t _monmod_config_traced_syscalls_show(struct kobject *kobj, 
                                            struct kobj_attribute *attr,
                                            char *buf);
ssize_t _monmod_config_traced_syscalls_store(struct kobject *kobj, 
                                             struct kobj_attribute *attr, 
				             const char *buf, size_t count);

#endif
