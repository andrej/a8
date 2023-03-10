#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
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
	bool is_exiting;
	struct config conf;
	struct communicator comm;
	struct batch_communicator *batch_comm;
	struct environment env;
	struct policy *policy;
	struct timeval start_tv;
#if ENABLE_CHECKPOINTING
	struct checkpoint_env checkpoint_env;
#endif
};

int monitor_init(struct monitor *monitor, int own_id, struct config *conf);

int monitor_destroy(struct monitor *monitor);

long monitor_handle_syscall(struct monitor * const monitor,
                            struct syscall_trace_func_stack * const stack);

#endif