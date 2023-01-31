#include "build_config.h"
#if ENABLE_CHECKPOINTING

#define _GNU_SOURCE
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <unistd.h>
#include "checkpointing.h"
#include "custom_syscalls.h"
#include "util.h"
#include "config.h"
#include "arch.h"
#include "trap_instr.h"
#include "syscall.h"
#include "syscall_trace_func.h"
#include "init.h"
#include "unprotected.h"


/* ************************************************************************** *
 * Internal Declarations                                                      *
 * ************************************************************************** */

static int overwrite_instruction(void *loc, void *instr, size_t len);
static struct checkpoint_env *signal_env = NULL;
static void monmod_handle_signal(int sig, siginfo_t *si, void *_context);
static void * handle_breakpoint(struct checkpoint_env *env, void *loc);
static int create_checkpoint(struct checkpoint_env *env,
                             struct breakpoint *b);
static int inject_breakpoint(struct checkpoint_env *env, void *loc, 
                             size_t instr_len, int interval);



/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int init_checkpoint_env(struct checkpoint_env *env, 
                        struct variant_config *config,
			void *monitor_start,
			size_t protected_len)
{
	env->monitor_start = monitor_start;
	env->protected_len = protected_len;

	/* Allocate shared memory for communication between checkpointed
	   waiting processes and the main process. */
	void *smem = NULL;
	Z_TRY(smem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
	                  MAP_SHARED | MAP_ANONYMOUS, -1, 0));
	env->smem = (struct checkpointing_smem *)smem;
	env->smem_length = page_size;
	NZ_TRY(sem_init(&env->smem->semaphore, 1, 1));

	/* Register our SIGTRAP signal handler for breakpoint handling. */
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = monmod_handle_signal;
	signal_env = env;
	NZ_TRY(sigaction(SIGTRAP, &sa, NULL));

	/* Inject all the breakpoints defined in the configuration. */
	if(config->n_breakpoints > MAX_N_BREAKPOINTS) {
		WARNF("Can only create %lu breakpoints, but configuration "
		      "requests %lu.\n", (unsigned long)MAX_N_BREAKPOINTS, 
		      config->n_breakpoints);
		return 1;
	}
	env->n_breakpoints = 0;
	for(size_t i = 0; i < config->n_breakpoints; i++) {
		// TODO add check that breakpoint is not in monitor space
		NZ_TRY(inject_breakpoint(env, config->breakpoints[i].pc,
		                         config->breakpoints[i].instr_len,
		                         config->breakpoints[i].interval));
	}


	return 0;
}

int restore_last_checkpoint(struct checkpoint_env *env)
{
	if(!env->last_checkpoint.valid) {
		return 1;
	}
	smem_put(&env->smem->semaphore, 
	         env->smem->message = CHECKPOINT_RESTORE);
	exit(0);
}


/* ************************************************************************** *
 * Internals                                                                  * 
 * ************************************************************************** */

static int inject_breakpoint(struct checkpoint_env *env, void *loc, 
                             size_t instr_len, int interval)
{
	uint64_t orig_instr = 0;
	memcpy(&orig_instr, loc, instr_len);
	NZ_TRY(overwrite_instruction(loc, trap_instr, trap_instr_len));
	size_t i = env->n_breakpoints;
	env->n_breakpoints++;
	env->breakpoints[i] = (struct breakpoint)
		{ loc, orig_instr, instr_len, interval, 0 };
	return 0;
}

static int 
__attribute ((section ("unprotected")))
overwrite_instruction(void *loc, void *instr, size_t len)
{
	void *page_aligned = (void *)((unsigned long long)loc & ~(page_size-1));
	NZ_TRY(unprotected_funcs.mprotect(page_aligned, page_size, PROT_WRITE));
	unprotected_funcs.memcpy(loc, instr, len);
	NZ_TRY(unprotected_funcs.mprotect(page_aligned, page_size, PROT_READ |
	                                                           PROT_EXEC));
	return 0;
}

static void 
__attribute__ ((section ("unprotected")))
monmod_handle_signal(int sig, siginfo_t *si, void *_context)
{
	ucontext_t *context = (ucontext_t *)_context;
	void *loc = (void *)UCONTEXT_PC(_context);
	void *new_loc = NULL;
	Z_TRY_EXCEPT(new_loc = handle_breakpoint(signal_env, loc),
	             exit(1));
	UCONTEXT_PC(_context) = (uint64_t)new_loc;
}

static void * 
__attribute__((section("unprotected")))
handle_breakpoint(struct checkpoint_env *env, void *loc)
{
	struct breakpoint *b = NULL;
	/* On x86, RIP is increased, and then SIGTRAP is raised, so we need to
	   rewind to before the instruction. On aarch64, SIGTRAP is raised 
	   before the instruction pointer is increased. */

#if ARCH_x86_64	
	loc -= trap_instr_len;  // Adjust PC before trap instruction
#endif

	if(NULL == env->in_breakpoint) {

		/* Find which breakpoint was hit. */
		for(size_t i = 0; i < env->n_breakpoints; i++) {
			if(env->breakpoints[i].loc == loc) {
				b = &env->breakpoints[i];
				break;
			}
		}
		Z_TRY_EXCEPT(b, return NULL);

		/* Trigger checkpointing mechanism. */
		if(b->hits % b->interval == 0) {
			NZ_TRY_EXCEPT(create_checkpoint(env, b),
			              return NULL);
			b->hits = 0;
		}
		b->hits++;

		/* Resume execution until the next instruction; insert a 
		   breakpoint after it so we can reinsert original breakpoint. 
		   */
		env->in_breakpoint = b;
		NZ_TRY_EXCEPT(overwrite_instruction(loc, &b->orig_instr, 
		                                    b->orig_instr_len),
			      return NULL);
		unprotected_funcs.memcpy(&b->orig_instr, 
		                         loc + b->orig_instr_len, 
					 trap_instr_len);
		NZ_TRY_EXCEPT(overwrite_instruction(loc + b->orig_instr_len,
		                                    trap_instr,
					            trap_instr_len),
			      return NULL);
	} else {
		/* We just single-stepped an instruction and need to reinsert
		   the breakpoint. */

		b = env->in_breakpoint;
		env->in_breakpoint = NULL;
		uint64_t orig_instr_2 = b->orig_instr;

		Z_TRY_EXCEPT(loc == b->loc + b->orig_instr_len,
		             return NULL);  // assert loc

		unprotected_funcs.memcpy(&b->orig_instr, 
		                         b->loc, b->orig_instr_len);
		NZ_TRY_EXCEPT(overwrite_instruction(b->loc, trap_instr, 
		                                    trap_instr_len),
			      return NULL);
		NZ_TRY_EXCEPT(overwrite_instruction(b->loc + b->orig_instr_len,
		                                    &orig_instr_2,
						    trap_instr_len),
		              return NULL);
	}

	return loc;
}

static int
__attribute__((section("unprotected")))
create_checkpoint(struct checkpoint_env *env, struct breakpoint *b)
{
	int s = 0;
	/* We perform a very lightweight, incomplete checkpointing by simply
	   forking a new copy of the process and holding it at this point until
	   signalled through shared memory that the process should continue. */
	
	/* First, kill previous checkpoint, if any. We only need the most 
	   recent. */
	if(env->last_checkpoint.valid) {
		smem_put(&env->smem->semaphore, 
		         env->smem->message = CHECKPOINT_DELETE);
		while(!smem_get(&env->smem->semaphore,
		                env->smem->done_flag));
		/* At this point, we are sure that we are memory-synchronized
		   with the checkpointed process, and it is about to exit --
		   it is guaranteed to not acquire the semaphore again, but not
		   necessarily dead yet. We call kill() to synchronize with its
		   death (either kill errors because child already exited, or
		   it succeeds -- in both cases after the call, the child is
		   gone). */
		kill(env->last_checkpoint.pid, SIGKILL);
	}

	/* Set message in shared memory to CHECKPOINT_HOLD before fork() to
	   avoid any race conditions. This causes the child to hold in a busy
	   loop. No memory synchronization mechanisms are needed here since we
	   just killed any previous checkpoint that may be trying to read. */
	env->smem->message = CHECKPOINT_HOLD;
	env->smem->done_flag = false;

	/* Fork creates a copy of current process state. */
	pid_t child = 0;
	LZ_TRY(child = unprotected_funcs.fork());
	if(0 == child) {
		/* Register self for tracing. */
		s = unprotected_funcs.monmod_init(unprotected_funcs.getpid(), 
		                                  env->monitor_start, 
		                                  env->protected_len,
		                                  &monmod_syscall_trusted_addr,
		                                  &monmod_syscall_trace_enter);
		if(0 != s) {
			return 1;
		}
		/* The child remains paused and waits until it gets asked to 
		   resume. */
		env->last_checkpoint.valid = false;
		enum checkpointing_message msg;
		do {
			msg = smem_get(&env->smem->semaphore,
			               env->smem->message);
			if(msg == CHECKPOINT_HOLD && unprotected_funcs.getppid() == 1) {
				/* Parent died before it was able to give us an
				   instruction, and we got reposessed by init;
				   treat this like a CHECKPOINT_DELETE message. 
				   */
				msg = CHECKPOINT_DELETE;
			}
			if(msg == CHECKPOINT_HOLD) {
				unprotected_funcs.usleep(20);
			}
		} while(msg == CHECKPOINT_HOLD);
		switch(msg) {
			case CHECKPOINT_DELETE: {
				smem_put(&env->smem->semaphore, 
				         env->smem->done_flag = true);
				unprotected_funcs.exit(0);
				break; /* unreachable */
			}
			case CHECKPOINT_RESTORE: {
				smem_put(&env->smem->semaphore, 
				         env->smem->done_flag = true);
				unprotected_funcs
					.monmod_unprotected_reprotect();
				return 0; /* resume execution out of 
				             signal handler */
			}
		}
	} else {
		/* While, in theory, the checkpoint may not be fully created
		   yet (not yet waiting for messages), it is safe to continue
		   without introducing a race. We know that the child will
		   eventually see any restore requests issued. */
		env->last_checkpoint.valid = true;
		env->last_checkpoint.pid = child;
		return 0;
	}
}


#endif