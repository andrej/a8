#ifndef CHECKPOINTING_H
#define CHECKPOINTING_H

#include "build_config.h"

#if ENABLE_CHECKPOINTING
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>
#include <sched.h>
#include <setjmp.h>
#include "config.h"
#include "trap_instr.h"
#include "environment.h"
#include "smem.h"

struct checkpoint {
	bool valid;
	pid_t pid;
};

struct breakpoint {
	void *loc;
	uint64_t orig_instr;
	size_t orig_instr_len;
	int interval;
	int hits; // reset after each interval
};

enum checkpointing_message {
	CHECKPOINT_HOLD,
	CHECKPOINT_RESTORE,
	CHECKPOINT_DELETE
};

struct checkpointing_smem {
	volatile enum checkpointing_message message;
	volatile bool done_flag;
};

#define checkpointing_smem_cast(env) \
	((struct checkpointing_smem *)(env)->smem->data)

struct checkpoint_env {
	struct environment *tracee_env;
	struct checkpoint last_checkpoint;
	struct breakpoint *in_breakpoint; /* if non-null, we are single stepping
	                                     after hitting this breakpoint */
	size_t n_breakpoints;
	struct breakpoint breakpoints[MAX_N_BREAKPOINTS];
	struct monmod_monitor_addr_ranges *addr_ranges;
	bool create_checkpoint;
	struct monitor *monitor;
#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
	struct smem *smem;
	size_t smem_length;
	jmp_buf jmp_buf;
#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	pid_t dumper_restorer_pid;
	volatile bool dumper_restorer_ready;
#endif
};

int init_checkpoint_env(struct checkpoint_env *env,
                        struct monitor *monitor,
                        struct environment *tracee_env,
                        struct variant_config *config,
			struct monmod_monitor_addr_ranges *addr_ranges);

int restore_last_checkpoint(struct checkpoint_env *env);

void syscall_handle_checkpointing(struct checkpoint_env *env);

#endif
#endif