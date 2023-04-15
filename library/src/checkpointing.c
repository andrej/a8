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
#include "monmod_syscall.h"
#include "syscall_trace_func.h"
#include "library_init.h"
#include "unprotected.h"
#include "environment.h"
#include "globals.h"
#include "exchanges.h"
#if ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
#include "dumper_restorer.h"
#endif


/* ************************************************************************** *
 * Internal Declarations                                                      *
 * ************************************************************************** */

static int overwrite_instruction(void *loc, void *instr, size_t len);
static struct checkpoint_env *signal_env = NULL;
static void monmod_handle_signal(int sig, siginfo_t *si, void *_context);
static void *handle_breakpoint(struct checkpoint_env *env, void *loc);
#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
static int create_fork_checkpoint(struct checkpoint_env *env);
#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
static int create_criu_checkpoint(struct checkpoint_env *env);
#endif
static int inject_breakpoint(struct checkpoint_env *env, void *loc, 
                             size_t instr_len, int interval);



/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int init_checkpoint_env(struct checkpoint_env *env, 
                        struct monitor *monitor,
                        struct environment *tracee_env,
                        struct variant_config *config,
			struct monmod_monitor_addr_ranges *addr_ranges)
{
	env->monitor = monitor;
	env->tracee_env = tracee_env;
	env->addr_ranges = addr_ranges;

#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
	/* Allocate shared memory for communication between checkpointed
	   waiting processes and the main process (for fork checkpointing). 
	   CRIU checkpointing uses signals exclusively for communication. */
	void *smem = NULL;
	Z_TRY(smem = mmap(NULL, monmod_page_size, PROT_READ | PROT_WRITE,
	                  MAP_SHARED | MAP_ANONYMOUS, -1, 0));
	env->smem = (struct checkpointing_smem *)smem;
	env->smem_length = monmod_page_size;
	NZ_TRY(sem_init(&env->smem->semaphore, 1, 1));
#endif

	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = monmod_handle_signal;
	signal_env = env;

#if ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	/* Start the dumper/restorer process that can invoke CRIU. This must be
	   the parent process, as CRIU dumps the children of a process. */
	env->dumper_restorer_ready = false;
	NZ_TRY(sigaction(SIGUSR1, &sa, NULL));
	pid_t child = fork();
	if(0 != child) {
		dumper_restorer_main(env, child);
		raise(SIGKILL);
		return 1; /* Should be unreachable. */
	}
#endif

	/* Register our SIGTRAP signal handler for breakpoint handling
	   (and synchronizing with dumper/restorer parent in case of CRIU
	   checkpointing). */
	NZ_TRY(sigaction(SIGTRAP, &sa, NULL));

#if ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	/* Wait for previously forked dumper/restorer to be ready. */
	while(!env->dumper_restorer_ready);
	env->dumper_restorer_pid = getppid();
#endif

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
		if(0 == config->breakpoints[i].interval) {
			// Setting interval to 0 disables checkpointing for that
			// location; easy way to temporarily disable
			continue;
		}
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
#if VERBOSITY >= 2
	SAFE_LOGF("<%d> Restoring last checkpoint.\n", getpid());
#endif
#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
	smem_put(&env->smem->semaphore, 
	         env->smem->message = CHECKPOINT_RESTORE);
#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	kill(env->dumper_restorer_pid, SIGUSR2);
	env->last_checkpoint.valid = false;
#endif
	exit(0);
}

void syscall_handle_checkpointing(struct checkpoint_env *env)
{
	/* We cannot successfully create a checkpoint from within the signal
	   handler in a breakpoint with CRIU. This workaround creates a
	   checkpoint after system call handler entry after an appropriate
	   flag was set in the breakpoint beforehand. */
	if(env->create_checkpoint) {
#if VERBOSITY >= 2
		SAFE_LOGF("<%d> Creating checkpoint.\n", getpid());
#endif
		SAFE_NZ_TRY(synchronize(env->monitor, CREATE_CP_EXCHANGE));
#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
		SAFE_NZ_TRY(create_fork_checkpoint(env));
#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
		SAFE_NZ_TRY(create_criu_checkpoint(env));
#endif
		env->create_checkpoint = false;
	}
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
	void *page_aligned = (void *)((unsigned long long)loc 
	                              & ~(monmod_page_size-1));
	NZ_TRY(unprotected_funcs.mprotect(page_aligned, monmod_page_size, 
	                                  PROT_WRITE));
	unprotected_funcs.memcpy(loc, instr, len);
	NZ_TRY(unprotected_funcs.mprotect(page_aligned, monmod_page_size,
	                                  PROT_READ | PROT_EXEC));
	return 0;
}

static void 
__attribute__ ((section ("unprotected")))
monmod_handle_signal(int sig, siginfo_t *si, void *_context)
{
	switch(sig) {
	case SIGTRAP: {
		ucontext_t *context = (ucontext_t *)_context;
		void *loc = (void *)UCONTEXT_PC(_context);
		void *new_loc = NULL;
		Z_TRY_EXCEPT(new_loc = handle_breakpoint(signal_env, loc),
			unprotected_funcs.exit(1));
		UCONTEXT_PC(_context) = (uint64_t)new_loc;
		break;
	}
#if ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
	case SIGUSR1: {
		signal_env->dumper_restorer_ready = true;
		break;
	}
#endif
	default: {
		unprotected_funcs.exit(1);
	}
	}
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
			env->create_checkpoint = true;
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

#if ENABLE_CHECKPOINTING == FORK_CHECKPOINTING
static int
create_fork_checkpoint(struct checkpoint_env *cenv)
{
	int s = 0;
	/* We perform a very lightweight, incomplete checkpointing by simply
	   forking a new copy of the process and holding it at this point until
	   signalled through shared memory that the process should continue. */
	
	/* First, kill previous checkpoint, if any. We only need the most 
	   recent. */
	if(cenv->last_checkpoint.valid) {
		smem_put(&cenv->smem->semaphore, 
		         cenv->smem->message = CHECKPOINT_DELETE);
		smem_await(!smem_get(&cenv->smem->semaphore,
		                     cenv->smem->done_flag));
		/* At this point, we are sure that we are memory-synchronized
		   with the checkpointed process, and it is about to exit --
		   it is guaranteed to not acquire the semaphore again, but not
		   necessarily dead yet. We call kill() to synchronize with its
		   death (either kill errors because child already exited, or
		   it succeeds -- in both cases after the call, the child is
		   gone). */
		kill_and_wait(cenv->last_checkpoint.pid);
	}

	/* Set message in shared memory to CHECKPOINT_HOLD before fork() to
	   avoid any race conditions. This causes the child to hold in a busy
	   loop. No memory synchronization mechanisms are needed here since we
	   just killed any previous checkpoint that may be trying to read. */
	cenv->smem->message = CHECKPOINT_HOLD;
	cenv->smem->done_flag = false;

	/* Fork creates a copy of current process state. */
	pid_t child = 0;
#if !USE_LIBVMA
	LZ_TRY(child = fork());
#else
	LZ_TRY(child = vmafork());
#endif
	if(0 == child) { // child
		s = checkpointed_environment_fix_up(cenv->tracee_env);
		cenv->breakpoints[0].hits = 0;
		smem_put(&cenv->smem->semaphore,
		         cenv->smem->done_flag = true);
			// Parent needs to synchronize with fix up
		if(0 != s) {
			return 1;
		}
		/* Register self for tracing. */
		s = monmod_init(
			getpid(), 
			&monmod_syscall_trusted_addr,
			&monmod_syscall_trace_enter,
			cenv->addr_ranges->overall_start,
			cenv->addr_ranges->overall_len,
			cenv->addr_ranges->code_start,
			cenv->addr_ranges->code_len,
			cenv->addr_ranges->protected_data_start,
			cenv->addr_ranges->protected_data_len);
		if(0 != s) {
			return 1;
		}
		/* The child remains paused and waits until it gets asked to 
		   resume. */
		cenv->last_checkpoint.valid = false;
		enum checkpointing_message msg;
		do {
			msg = smem_get(&cenv->smem->semaphore,
			               cenv->smem->message);
			if(msg == CHECKPOINT_HOLD && getppid() == 1) {
				/* Parent died before it was able to give us an
				   instruction, and we got reposessed by init;
				   treat this like a CHECKPOINT_DELETE message. 
				   */
				msg = CHECKPOINT_DELETE;
			}
			if(msg == CHECKPOINT_HOLD) {
				sched_yield();
			}
		} while(msg == CHECKPOINT_HOLD);
		switch(msg) {
			case CHECKPOINT_DELETE: {
				smem_put(&cenv->smem->semaphore, 
				         cenv->smem->done_flag = true);
				exit(0);
				break; /* unreachable */
			}
			case CHECKPOINT_RESTORE: {
				smem_put(&cenv->smem->semaphore, 
				         cenv->smem->done_flag = true);
				kill_and_wait(getppid());
				/* Immediately create a copy of the current
				   checkpoint state upon restore. */
				SAFE_NZ_TRY(create_fork_checkpoint(cenv));
				return 0; /* resume execution out of 
				             syscall handler */
			}
		}
	} else {
		smem_await(!smem_get(&cenv->smem->semaphore,
		                     cenv->smem->done_flag));
		smem_put(&cenv->smem->semaphore,
		         cenv->smem->done_flag = false);
		cenv->last_checkpoint.valid = true;
		cenv->last_checkpoint.pid = child;
		return 0;
	}
}

#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
static int create_criu_checkpoint(struct checkpoint_env *cenv)
{
	cenv->dumper_restorer_ready = false;
	SAFE_NZ_TRY(kill(cenv->dumper_restorer_pid, SIGUSR1));
	/* We wait for the CRIU dump to complete. Note that this means the
	   dump will capture some iteration of the following loop; i.e. we
	   will resume execution from that loop when a checkpoint is restored.
	   Therfore, a SIGUSR1 will need to be sent upon restore to get the
	   restored image out of this loop! */
	int wait_sig;
	sigset_t wait_sigset;
	sigemptyset(&wait_sigset);
	sigaddset(&wait_sigset, SIGUSR1);
	sigwait(&wait_sigset, &wait_sig);
	cenv->last_checkpoint.valid = true;
	cenv->last_checkpoint.pid = getpid();
	return 0;
}
#endif

#endif