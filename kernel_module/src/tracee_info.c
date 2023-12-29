#include <linux/slab.h>
#ifndef TEST_H
#include <linux/spinlock.h>
#endif
#include "tracee_info.h"

/* ************************************************************************** *
 * Globals                                                                    *
 * ************************************************************************** */

/* Held whenever tracee infos are added or removed. Not held by readers. */
DEFINE_SPINLOCK(tracee_info_mutex);

struct tracee tracees[MAX_N_TRACEES] = {};

/* The following flag is set to false by the free_tracee_infos() function to 
   ensure no tracee infos are added concurrently after free was called, since 
   this occurs only upon module exit. */
static bool may_add_tracee_info = true;


/* ************************************************************************** *
 * Internals                                                                  *
 * ************************************************************************** */

void _del_tracee_info_synchronized(struct tracee *tracee)
{
	/* Set tracee state to STALE. This means get_tracee_info will not 
	   return any new references to this particular tracee. We can then
	   safely wait for all threads of execution that still have a reference
	   to finish reading. */
	WRITE_ONCE(tracee->state, TRACEE_INFO_STALE);

	//BUG_ON(rcu_read_lock_held());
	//synchronize_rcu();
	/* At this point, there are no more references to tracee floating 
	   around. */
#if MONMOD_MONITOR_PROTECTION & MONMOD_MONITOR_COMPARE_PROTECTED
	if(NULL != tracee->monitor_code_copy) {
		kfree(tracee->monitor_code_copy);
	}
#endif
	monmod_tracee_config_free(&tracee->config);
	if(NULL != tracee->entry_info.custom_data) {
		kfree(tracee->entry_info.custom_data);
	}
	WRITE_ONCE(tracee->state, TRACEE_INFO_FREE);
}


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

struct tracee *add_tracee_info(pid_t pid)
{
	unsigned long flags;
	size_t free_slot;

	WARN_ON(!rcu_read_lock_held());
	spin_lock_irqsave(&tracee_info_mutex, flags);

	if(!may_add_tracee_info) {
		goto abort1;
	}
	for(free_slot = 0; free_slot < MAX_N_TRACEES; free_slot++)
	{
		if(TRACEE_INFO_FREE == tracees[free_slot].state) {
			break;
		}
	}
	if(free_slot >= MAX_N_TRACEES) {
		goto abort1;
	}

	if(0 != monmod_tracee_config_init(pid, &tracees[free_slot].config)) {
		goto abort1;
	}
	tracees[free_slot].id = free_slot;
	tracees[free_slot].pid = pid;
	tracees[free_slot].state = TRACEE_INFO_VALID;

	spin_unlock_irqrestore(&tracee_info_mutex, flags);
	return &tracees[free_slot];
abort1:
	spin_unlock_irqrestore(&tracee_info_mutex, flags);
	return NULL;
}


int del_tracee_info(struct tracee *tracee)
{
	unsigned long flags;
	size_t idx;

	spin_lock_irqsave(&tracee_info_mutex, flags);

	idx = tracee - &tracees[0];
	if(MAX_N_TRACEES < idx) {
		goto abort1;
	}

	_del_tracee_info_synchronized(tracee);

	spin_unlock_irqrestore(&tracee_info_mutex, flags);
	return 0;
abort1:
	spin_unlock_irqrestore(&tracee_info_mutex, flags);
	return 1;
}

int free_tracee_infos()
{
	size_t i;
	unsigned long flags;
	spin_lock_irqsave(&tracee_info_mutex, flags);
	may_add_tracee_info = false;
	for(i = 0; i < MAX_N_TRACEES; i++) {
		if(TRACEE_INFO_VALID != tracees[i].state) {
			/* For stale ones, they will be removed by whoever
			   set their state as stale. */
			continue;
		}
		_del_tracee_info_synchronized(&tracees[i]);
	}
	spin_unlock_irqrestore(&tracee_info_mutex, flags);
	return 0;
}
