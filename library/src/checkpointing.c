#include "build_config.h"
#if ENABLE_CHECKPOINTING

#define _GNU_SOURCE
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <unistd.h>
#include <netinet/in.h>
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
	
	Z_TRY(env->smem = smem_init(sizeof(struct checkpointing_smem)));
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
#if USE_LIBVMA == USE_LIBVMA_LOCAL
	pid_t child = original_fork();
#else
	pid_t child = fork();
#endif
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
#if USE_LIBVMA == USE_LIBVMA_LOCAL
	comm_destroy(&monitor.comm);
#endif
	smem_put(env->smem, 
	         ((struct checkpointing_smem *)env->smem->data)
			 	->message = CHECKPOINT_RESTORE);
	/* Do NOT use env->smem after this point. It is now shared between the
	   restored checkpoint and its child checkpoint! */
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
		SAFE_NZ_TRY(synchronize(env->monitor, exchange_checkpoint_create));
#if VERBOSITY >= 1
		/* Log after synchronizing. We might not get to here if there
		   was a disagreement during synchronization. */
		struct timeval tv, duration;
		SAFE_NZ_TRY(gettimeofday(&tv, NULL));
		timersub(&tv, &env->monitor->start_tv, &duration);
		if(!env->last_checkpoint.valid) {
			SAFE_LOGF("<%d> Creating first checkpoint after "
			          "%ld.%06ld seconds.\n", getpid(),
				  duration.tv_sec,
				  duration.tv_usec);
		}
#endif
#if VERBOSITY >= 2
		if(env->last_checkpoint.valid) {
			SAFE_LOGF("<%d> Creating checkpoint.\n", getpid());
		}
#endif
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
/* ************************************************************************** *
 * Fork Checkpointing                                                         *
 * ************************************************************************** */

#if USE_LIBVMA == USE_LIBVMA_LOCAL
/* Used for fork checkpointing when using libVMA, since libVMA does not persist
   connections across fork. */
static void _recreate_connections()
{
	struct sockaddr addr = monitor.comm.self.addr;
	((struct sockaddr_in *)&addr)->sin_port += 1;
	in_port_t own_port;
	comm_destroy(&monitor.comm);
	SAFE_LZ_TRY(own_port = comm_init(&monitor.comm, monitor.own_id, &addr));

	for(size_t i = 0; i < monitor.conf.n_variants; i++) {
		if(monitor.conf.variants[i].id == monitor.own_id) {
			continue;
		}
		usleep(200000*monitor.own_id);
			/* ... if you have a better idea, I'm all ears. We are
			   in the child process and cannot use parents socket
			   to synchronize. */
		struct sockaddr *other_addr = &monitor.conf.variants[i].addr;
		((struct sockaddr_in *)other_addr)->sin_port += 1;
		SAFE_NZ_TRY(comm_connect(&monitor.comm, 
		                    monitor.conf.variants[i].id, 
		                    other_addr));
	}
}
#endif

/* This is the "main()" of a fork checkpoint that is waiting to be restored or
   deleted. It just waits, exits if no longer needed, or continues execution
   at the checkpointed location upon request, along with duplicating itself for
   another later restore if needed. */
static int _fork_checkpoint_main(struct checkpoint_env *cenv, pid_t parent)
{
	int s = 0;
	s = checkpointed_environment_fix_up(cenv->tracee_env);
	cenv->breakpoints[0].hits = 0;
	// Parent needs to synchronize with fix up
	smem_put(cenv->smem, checkpointing_smem_cast(cenv)->done_flag = true);
	if(0 != s) {
		return 1;
	}
	/* Register self for tracing. */
	s = monmod_init(getpid(), 
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
	/* The child remains paused and waits until it gets asked to resume. */
	enum checkpointing_message msg;
	do {
		msg = smem_get(cenv->smem, uint64_t,
					   checkpointing_smem_cast(cenv)->message);
		if(msg == CHECKPOINT_HOLD && getppid() != parent) {
			/* Parent died before it was able to give us an instruction, and we 
			   got reposessed by init; treat this case like a CHECKPOINT_DELETE 
			   message.  */
			msg = CHECKPOINT_DELETE;
		}
		if(msg == CHECKPOINT_HOLD) {
			sched_yield();
		}
	} while(msg == CHECKPOINT_HOLD);
	smem_put(cenv->smem,
			 checkpointing_smem_cast(cenv)->message = CHECKPOINT_HOLD);
	switch(msg) {
		case CHECKPOINT_DELETE: {
			smem_put(cenv->smem, 
					 checkpointing_smem_cast(cenv)->done_flag = true);
			exit(0);
			break; /* unreachable */
		}
		case CHECKPOINT_RESTORE: {
			smem_put(cenv->smem,
					 checkpointing_smem_cast(cenv)->done_flag = true);
			// After putting this message, the parent will now exit momentarily. 
			while(parent == getppid());
#if USE_LIBVMA == USE_LIBVMA_LOCAL
			_recreate_connections();
#endif
			/* This longjump resumes execution right before creation of the
			   checkpoint. This duplicates this current checkpoint if we want to
			   restore it again later. We use setjmp/longjmp instead of a 
			   recursive create_fork_checkpoint() call to limit stack growth. */
			longjmp(cenv->jmp_buf, 0);
			return 0; /* unreachable */
		}
	}
}

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
		smem_put(cenv->smem, 
		         checkpointing_smem_cast(cenv)->message = CHECKPOINT_DELETE);
		smem_await(!smem_get(cenv->smem,
		                     uint64_t,
		                     checkpointing_smem_cast(cenv)->done_flag));
		/* At this point, we are sure that we are memory-synchronized
		   with the checkpointed process, and it is about to exit --
		   it is guaranteed to not acquire the semaphore again, but not
		   necessarily dead yet. We call kill() to synchronize with its
		   death (either kill errors because child already exited, or
		   it succeeds -- in both cases after the call, the child is
		   gone). */
		kill_and_wait(cenv->last_checkpoint.pid);
		cenv->last_checkpoint.valid = false;
	}

	/* This is the point from which execution will continue in the checkpointed
	   child process upon resotre. By restoring to this point, the checkpoint
	   will immediately be duplicated (re-created) upon restore. This allows
	   restoring to the "same" checkpoint multiple times. */
	setjmp(cenv->jmp_buf);

	/* Set message in shared memory to CHECKPOINT_HOLD before fork(). No memory 
	   synchronization mechanisms are needed here since we just killed any 
	   previous checkpoint that may be trying to read, and the new checkpoint 
	   has not forked yet. If we land here through the setjmp above, i.e. this
	   is a freshly restored ceckpoint, note that the parent process technically
	   still has access to cenv->smem; however, it will exit momentarily and not
	   use it, so no need to synchronize with it either. */
	checkpointing_smem_cast(cenv)->message = CHECKPOINT_HOLD;
	checkpointing_smem_cast(cenv)->done_flag = false;

	/* Fork creates a copy of most of the current process state. */
	pid_t parent = getpid();
	pid_t child = 0;
#if USE_LIBVMA != USE_LIBVMA_LOCAL
	LZ_TRY(child = fork());
#else
	LZ_TRY(child = vmafork());
#endif
	if(0 == child) { // child; this is the checkpoint
		s = _fork_checkpoint_main(cenv, parent);
		if(0 != s) {
			printf("Error in checkpoint child process.\n");
			exit(s);
		}
		return 0;
	} else {  // parent; this will continue executing regularly
		smem_await(!smem_get(cenv->smem,
		                     uint64_t,
		                     checkpointing_smem_cast(cenv)->done_flag));
		smem_put(cenv->smem,
		         checkpointing_smem_cast(cenv)->done_flag = false);
		cenv->last_checkpoint.valid = true;
		cenv->last_checkpoint.pid = child;
		return 0;
	}
}


#elif ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING
/* ************************************************************************** *
 * CRIU Checkpointing                                                         *
 * ************************************************************************** */
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
