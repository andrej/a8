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
#else
#endif

#include <stdbool.h>
#include "build_config.h"
#include "arch.h"

/* ************************************************************************** *
 * Macros                                                                     *
 * ************************************************************************** */

#define MONMOD_BITS_PER_MASK 64
#define MONMOD_N_SYSCALL_MASKS ((__NR_syscalls + MONMOD_BITS_PER_MASK - 1) \
                                / MONMOD_BITS_PER_MASK)

#define MONMOD_NO_SYSCALL (__NR_syscalls+1)

#define _monmod_syscall_mask_index(no)  ((no) / MONMOD_BITS_PER_MASK)
#define _monmod_syscall_mask_offset(no) ((no) % MONMOD_BITS_PER_MASK)

/* ************************************************************************** *
 * Data Types & Global Variables                                              *
 * ************************************************************************** */

struct monmod_tracee_config {
        struct kobject kobj;
        bool active;
};

struct monmod_config {
	struct kobject kobj;
    size_t n_tracees;
	u64 syscall_masks[MONMOD_N_SYSCALL_MASKS];
};

extern struct monmod_config monmod_global_config;


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_config_init(void);
void monmod_config_free(void);

int monmod_tracee_config_init(pid_t pid, struct monmod_tracee_config *conf);
void monmod_tracee_config_free(struct monmod_tracee_config *conf);

static inline int monmod_syscall_is_active(u64 syscall_no)
{
    const int index = _monmod_syscall_mask_index(syscall_no);
    const int offset = _monmod_syscall_mask_offset(syscall_no);
#if !MONMOD_SKIP_SANITY_CHECKS
    if(index >= MONMOD_N_SYSCALL_MASKS) {
        printk(KERN_WARNING "monmod: Out-of-bounds system call %ld with index "
               "%d and offset %d.\n", syscall_no, index, offset);
        return 0;
    }
#endif
    return (monmod_global_config.syscall_masks[index] >> offset) & 0x1;
}

int monmod_syscall_activate(u64 syscall_no);
int monmod_syscall_deactivate(u64 syscall_no);


/* ************************************************************************** *
 * Internals                                                                  *
 * (Exported in test header anyways so we can test them.)                     *
 * ************************************************************************** */

#define GLOBAL_ATTRIBUTES(X) \
    X(tracee_pids) \
    X(untraced_syscalls)

#define TRACEE_ATTRIBUTES(X) \

#define CONFIG_SHOW_PROT(name) \
        ssize_t _monmod_config_ ## name ## _show(struct kobject *kobject, \
                                                 struct kobj_attribute *attr, \
                                                 char *buf);
#define CONFIG_STORE_PROT(name) \
        ssize_t _monmod_config_ ## name ## _store(struct kobject *kobject, \
                                                  struct kobj_attribute *attr, \
                                                  const char *buf, \
                                                  size_t count);

GLOBAL_ATTRIBUTES(CONFIG_SHOW_PROT)
TRACEE_ATTRIBUTES(CONFIG_SHOW_PROT)
GLOBAL_ATTRIBUTES(CONFIG_STORE_PROT)
TRACEE_ATTRIBUTES(CONFIG_STORE_PROT)

#endif
