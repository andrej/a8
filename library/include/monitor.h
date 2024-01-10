#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "communication.h"
#include "batched_communication.h"
#include "environment.h"
#include "config.h"
#include "checkpointing.h"
#include "policy.h"
#include "syscall_trace_func.h"

struct monitor {
	int own_id;
	int leader_id;
	bool is_leader;
	struct config conf;
	struct communicator comm;
	struct batch_communicator *batch_comm;
	struct environment env;
	struct policy *policy;
	struct timeval start_tv;
	unsigned long ancestry;  // just for log numbers
#if ENABLE_CHECKPOINTING
	struct monmod_monitor_addr_ranges addr_ranges;
	struct checkpoint_env *checkpoint_env;
#endif
	long random_seed;
};

void register_monitor_in_kernel();

int monitor_init(struct monitor *monitor, int own_id, struct config *conf);

int monitor_init_comm(struct communicator *comm, struct config *conf, int id);

int monitor_destroy(struct monitor *monitor);

/**
 * Negotiates new connections bertween all variants on available open ports and
 * initializes those connections in a new communicator, child_comm.
 * 
 * Must be called simulatenously in all variants.
 */
int monitor_arbitrate_child_comm(struct monitor *parent_monitor,
                                 struct communicator *child_comm);

/**
 * Initializes the child monitor pointed to by `monitor` to be a close
 * replica of `parent_monitor`, with the following changes:
 *  - The logging timestamp is reset to zero.
 *  - The communicator passed in is used instead.
 *  - The PIDs are adjusted to the new child PIDs.
 * 
 * Used in fork/clone handlers.
 */
int monitor_child_fix_up(struct monitor *monitor, 
                         struct communicator *child_comm);

/**
 * Initialize (seed) random number generator used by monitor.
 */
static inline int monitor_init_random(struct monitor *monitor, int add_seed)
{
	char *prev_state = NULL;
	const long seed = time(NULL) * (monitor->own_id + 1) * monitor->ancestry
	                  + add_seed;
	SAFE_Z_TRY(prev_state = initstate(seed, (char *)&monitor->random_seed, 
				                      sizeof(monitor->random_seed)));
	setstate(prev_state);
}

/**
 * Return a random double.
 */
static inline double monitor_random(const struct monitor *monitor)
{
	char * const prev_state = setstate((char *)&monitor->random_seed);
	const long r = random();
	setstate(prev_state);
	return (double)r / RAND_MAX;
}


#endif