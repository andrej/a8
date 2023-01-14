#ifndef CHECKPOINTING_H
#define CHECKPOINTING_H

#include "build_config.h"

#if ENABLE_CHECKPOINTING
#include <unistd.h>
#include <stdint.h>
#include "config.h"
#include "trap_instr.h"

struct checkpoint {
	pid_t pid;
};

struct breakpoint {
	void *loc;
	uint64_t orig_instr;
	size_t orig_instr_len;
	int interval;
	int hits; // reset after each interval
};

struct checkpoint_env {
	void *smem;
	size_t smem_length;
	struct checkpoint last_checkpoint;
	struct breakpoint *in_breakpoint; /* if non-null, we are single stepping
	                                     after hitting this breakpoint */
	size_t n_breakpoints;
	struct breakpoint breakpoints[MAX_N_BREAKPOINTS];
};

int init_checkpoint_env(struct checkpoint_env *env,
                        struct variant_config *config);


#endif
#endif