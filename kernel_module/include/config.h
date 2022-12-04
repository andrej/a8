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
#include <linux/uaccess.h>
#endif

#include "build_config.h"
#include "arch.h"

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
#ifndef TEST_H
        void __user *trusted_addr;
#else
        void *trusted_addr;
#endif
        long active;
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

#define CONFIG_SHOW_PROT(name) \
        ssize_t _monmod_config_ ## name ## _show(struct kobject *kobj, \
                                                 struct kobj_attribute *attr, \
                                                 char *buf);
#define CONFIG_STORE_PROT(name) \
        ssize_t _monmod_config_ ## name ## _store(struct kobject *kobj, \
                                                  struct kobj_attribute *attr, \
                                                  const char *buf, \
                                                  size_t count);

CONFIG_SHOW_PROT(pid)
CONFIG_STORE_PROT(pid)

CONFIG_SHOW_PROT(addr)
CONFIG_STORE_PROT(addr)

CONFIG_SHOW_PROT(active)
CONFIG_STORE_PROT(active)

CONFIG_SHOW_PROT(traced_syscalls)
CONFIG_STORE_PROT(traced_syscalls)

#endif
