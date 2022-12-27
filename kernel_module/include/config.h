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

#define MONMOD_MAX_N_TRACEES 8
#define MONMOD_NO_SYSCALL (__NR_syscalls+1)


/* ************************************************************************** *
 * Data Types & Global Variables                                              *
 * ************************************************************************** */

struct monmod_tracee_config {
        struct kobject kobj;
        #ifndef TEST_H
                void __user *monitor_start;
                size_t monitor_len;
                void __user *trusted_addr;
                void __user *trace_func_addr;
        #else
                void __user *monitor_start;
                size_t monitor_len;
                void *trusted_addr;
                void *trace_func_addr;
        #endif
        bool active;
};

struct monmod_config {
	struct kobject kobj;
        size_t n_tracees;
	pid_t tracee_pids[MONMOD_MAX_N_TRACEES]; // 0 == unused
        struct monmod_tracee_config tracees[MONMOD_MAX_N_TRACEES];
        long active;
	u64 syscall_masks[MONMOD_N_SYSCALL_MASKS];
};

extern struct monmod_config monmod_global_config;


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_config_init(void);
void monmod_config_free(void);

int monmod_add_tracee_config(pid_t pid);
int monmod_del_tracee_config(size_t idx);

static inline __attribute__((__always_inline__))
bool monmod_is_pid_traced(pid_t pid)
{
        int i = 0;
        for(; i < MONMOD_MAX_N_TRACEES; i++) {
                if(monmod_global_config.tracee_pids[i] == pid) {
                        return true;
                }
        }
        return false;
}
struct monmod_tracee_config *monmod_get_tracee_config(pid_t pid);

int monmod_syscall_is_active(u64 syscall_no);
int monmod_syscall_activate(u64 syscall_no);
int monmod_syscall_deactivate(u64 syscall_no);


/* ************************************************************************** *
 * Internals                                                                  *
 * (Exported in test header anyways so we can test them.)                     *
 * ************************************************************************** */

int _monmod_syscall_mask_index(u64 syscall_no);
int _monmod_syscall_mask_offset(u64 syscall_no);

int monmod_tracee_config_init(size_t idx);
void monmod_tracee_config_free(size_t idx);

#define CONFIG_SHOW_PROT(name) \
        ssize_t _monmod_config_ ## name ## _show(struct kobject *kobject, \
                                                 struct kobj_attribute *attr, \
                                                 char *buf);
#define CONFIG_STORE_PROT(name) \
        ssize_t _monmod_config_ ## name ## _store(struct kobject *kobject, \
                                                  struct kobj_attribute *attr, \
                                                  const char *buf, \
                                                  size_t count);

CONFIG_SHOW_PROT(tracee_pids)
CONFIG_STORE_PROT(tracee_pids)

CONFIG_SHOW_PROT(tracee_pids_add)
CONFIG_STORE_PROT(tracee_pids_add)

CONFIG_SHOW_PROT(active)
CONFIG_STORE_PROT(active)

CONFIG_SHOW_PROT(untraced_syscalls)
CONFIG_STORE_PROT(untraced_syscalls)

CONFIG_SHOW_PROT(trusted_addr)
CONFIG_STORE_PROT(trusted_addr)

CONFIG_SHOW_PROT(trace_func_addr)
CONFIG_STORE_PROT(trace_func_addr)

#endif
