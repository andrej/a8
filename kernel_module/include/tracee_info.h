#ifndef TRACEE_INFO_H
#define TRACEE_INFO_H

#ifndef TEST_H
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#endif
#include "config.h"


/* ************************************************************************** *
 * Macros                                                                     *
 * ************************************************************************** */
#define MAX_N_TRACEES 8


/* ************************************************************************** *
 * Data Types                                                                 *
 * ************************************************************************** */
struct intercepted_syscall {
	long syscall_no;
	bool do_inject_return;
	long inject_return;
	void *custom_data;
#if MONMOD_LOG_VERBOSITY >= 1
	bool do_log;
#endif
};

enum tracee_info_state {
	/* This slot in the global tracee_info array is free. Any stored date 
	   is to be considered meaningless. A new tracee_info can be added 
	   in this place. */
	TRACEE_INFO_FREE,
	/* This slot is occupied with valid tracee info. */
	TRACEE_INFO_VALID,
	/* This slot is to be removed, but some threads of execution still have
	   valid references they rely on.
	   No new references may be returned, or a race will occur. But anyone 
	   that obtained a reference before this turned stale will be 
	   waited-for. */
	TRACEE_INFO_STALE
};

struct tracee {
	enum tracee_info_state state;
	pid_t pid;
	struct monmod_tracee_config config;
	struct intercepted_syscall entry_info;
};


/* ************************************************************************** *
 * Globals                                                                    *
 * ************************************************************************** */

extern struct tracee tracees[MAX_N_TRACEES];


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

/**
 * Return a pointer to a struct tracee for the given PID.
 * 
 * NOTE: This call and all data referencing the pointer must be wrapped in 
 * rcu_read_lock() and rcu_read_unlock(). The data may become invalid after
 * the rcu_read_unlock().
 * 
 * NOTE: It is assumed that only one thread of execution accesses one tracee
 * info (its own). Modifying tracee infos (except for the `state`) is therefore
 * okay without any locking/synchronization. This means you can use the returned
 * pointer to write to the data as well. Synchronization is only there to ensure
 * we do not have racing adds/deletes of entire processes/thread infos.
 */
static inline struct tracee *get_tracee_info(pid_t pid)
{
	size_t i;
	WARN_ON(!rcu_read_lock_held());
	for(i = 0; i < MAX_N_TRACEES; i++) {
		if(TRACEE_INFO_VALID != tracees[i].state) {
			continue;
		}
		if(pid == tracees[i].pid) {
			return &tracees[i];
		}
	}
	return NULL;
}

/**
 * Add a tracee for the given PID.
 * 
 * NOTE: rcu_read_lock() must be held, since a pointer to the added tracee_info
 * will be returned. This pointer would be meaningless if not in an RCU read
 * block, since it may become removed/invalid as soon as the function exits.
 */
struct tracee *add_tracee_info(pid_t pid);

/**
 * Remove a tracee, freeing all associated resources.
 */
int del_tracee_info(struct tracee *tracee);

/**
 * Free all tracee infos.
 */
int free_tracee_infos(void);

#endif