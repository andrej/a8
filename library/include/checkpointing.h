#ifndef CHECKPOINTING_H
#define CHECKPOINTING_H

#include "build_config.h"

#if ENABLE_CHECKPOINTING
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>
#include "config.h"
#include "trap_instr.h"

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
	sem_t semaphore;
	volatile enum checkpointing_message message;
	volatile bool done_flag;
};

#define smem_get(sem, smem_val) ({ \
	volatile uint64_t val = 0; \
	while(0 != unprotected_funcs.sem_wait(sem)); \
	val = smem_val; \
	unprotected_funcs.sem_post(sem); \
	val; \
})

#define smem_put(sem, put_op) ({ \
	while(0 != unprotected_funcs.sem_wait(sem)); \
	put_op; \
	unprotected_funcs.sem_post(sem); \
})

struct checkpoint_env {
	struct checkpoint last_checkpoint;
	struct breakpoint *in_breakpoint; /* if non-null, we are single stepping
	                                     after hitting this breakpoint */
	size_t n_breakpoints;
	struct breakpoint breakpoints[MAX_N_BREAKPOINTS];
	/* The following two denote the monitor location in shared memory; 
	   information needed by the monmod_init call in child checkpoints. */
	void *monitor_start;
	size_t protected_len;
#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
	struct checkpointing_smem *smem;
	size_t smem_length;
#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	pid_t dumper_restorer_pid;
	volatile bool dumper_restorer_ready;
#endif
};

int init_checkpoint_env(struct checkpoint_env *env,
                        struct variant_config *config,
			void *monitor_start,
			size_t protected_len);

int restore_last_checkpoint(struct checkpoint_env *env);

void restore_checkpoint_if_needed(struct checkpoint_env *env, 
                                  int restore_interval);

#endif
#endif