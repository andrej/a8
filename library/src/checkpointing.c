#include "build_config.h"
#if ENABLE_CHECKPOINTING

#define _GNU_SOURCE
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include "checkpointing.h"
#include "util.h"
#include "config.h"
#include "arch.h"
#include "trap_instr.h"


/* ************************************************************************** *
 * Internal Declarations                                                      *
 * ************************************************************************** */

static int overwrite_instruction(void *loc, void *instr, size_t len);
static struct checkpoint_env *signal_env = NULL;
static void monmod_handle_signal(int sig, siginfo_t *si, void *_context);
static void * handle_breakpoint(struct checkpoint_env *env, void *loc);
static int create_checkpoint(struct checkpoint_env *env);
static int inject_breakpoint(struct checkpoint_env *env, void *loc, 
                             size_t instr_len, int interval);


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int init_checkpoint_env(struct checkpoint_env *env, 
                        struct variant_config *config)
{
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

static int overwrite_instruction(void *loc, void *instr, size_t len)
{
	void *page_aligned = (void *)((unsigned long long)loc & ~(page_size-1));
	NZ_TRY(mprotect(page_aligned, page_size, PROT_WRITE));
	memcpy(loc, instr, len);
	NZ_TRY(mprotect(page_aligned, page_size, PROT_READ | PROT_EXEC));
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
			create_checkpoint(env);
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
		memcpy(&b->orig_instr, loc + b->orig_instr_len, trap_instr_len);
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

		memcpy(&b->orig_instr, b->loc, b->orig_instr_len);
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
create_checkpoint(struct checkpoint_env *env)
{
	char msgbuf[] = "create_checkpoint hit.\n";
	write(1, msgbuf, sizeof(msgbuf));
}

void
__attribute__((section("unprotected")))
paused_loop()
{
	// Wait for restore request to unpause
}

#endif