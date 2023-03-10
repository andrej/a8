
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "monitor.h"
#include "syscall_trace_func.h"
#include "util.h"
#include "handlers.h"
#include "policy.h"
#include "globals.h"
#include "arch.h"
#include "unprotected.h"
#include "replication.h"

/* ************************************************************************** *
 * Global Variables                                                           *
 * ************************************************************************** */

struct monitor monitor;


/* ************************************************************************** *
 * Local Variables                                                            *
 * ************************************************************************** */

char syscall_log_buf[1024];
struct timeval start_tv;


/* ************************************************************************** *
 * Local Forward Declarations                                                 *
 * ************************************************************************** */

static int
syscall_dispatch_apply_policy(int dispatch, struct syscall_info *canonical,
                              struct policy *policy);
static int
syscall_check_dispatch_sanity(int dispatch,
                              struct syscall_handler const *const handler,
                              struct syscall_info *actual,
                              struct syscall_info *canonical);

static void
syscall_handle_divergence(struct syscall_handler const *const handler,
                          struct syscall_info *actual,
                          struct syscall_info *canonical);

static void syscall_execute_locally(struct syscall_handler const *const handler,
                                    struct syscall_info *actual, 
                                    struct syscall_info *canonical);

static void terminate(struct monitor * const monitor);


/* ************************************************************************** *
 * Initialization                                                             *
 * ************************************************************************** */

int monitor_init(struct monitor *monitor, int own_id, struct config *conf)
{
	struct variant_config *own_variant_conf;
	void *monitor_start = NULL;
	size_t monitor_len = 0, protected_len = 0;

	memset(monitor, 0, sizeof(monitor));

	monitor->own_id = own_id;
	monitor->leader_id = conf->leader_id;
	monitor->is_leader = conf->leader_id == own_id;
	Z_TRY(monitor->policy = policy_from_str(conf->policy));

	Z_TRY_EXCEPT(own_variant_conf = get_variant(conf, own_id), exit(1));

	/* Initialize Individual Basic Monitoring Components */
	env_init(&monitor->env, monitor->is_leader);
#if MEASURE_TRACING_OVERHEAD
	/* If we are only interested in measuring the tracing overhead, register
	   the monitor now and exit, before setting up any of the network
	   connections or checkpointing environment. */
	NZ_TRY_EXCEPT(monmod_init(env.pid, 
	                          monitor_start, 
	                          protected_len,
	                          &monmod_syscall_trusted_addr,
	                          &monmod_syscall_trace_enter),
	              exit(1));
	return 0;
#endif

	LZ_TRY_EXCEPT(comm_init(&monitor->comm, own_id, 
	                        &own_variant_conf->addr), 
	              exit(1));
	for(size_t i = 0; i < conf->n_variants; i++) {
		if(conf->variants[i].id == own_id) {
			continue;
		}
		NZ_TRY_EXCEPT(comm_connect(&monitor->comm, conf->variants[i].id, 
		                           &conf->variants[i].addr),
		              exit(1));
	}

	NZ_TRY_EXCEPT(replication_init(monitor, conf->replication_batch_size),
	              exit(1));

	/* Checkpointing */
#if ENABLE_CHECKPOINTING
	/* The checkpointing environment needs to be initialized before 
	   the monitor is registered: CRIU checkpointing forks a new
	   dumper/restorer parent process, and the child process is the one
	   that should register to be monitored. */
	NZ_TRY_EXCEPT(init_checkpoint_env(&checkpoint_env,
	                                  own_variant_conf,
	                                  monitor_start, protected_len),
	              exit(1));
	env.pid = getpid();
#endif

	/* -- Register Tracing With Kernel Module -- */

	/* Find the pages this module is loaded on. These pages will be 
	   protected by the kernel to remain inaccessible for other parts of
	   the program. */
	NZ_TRY_EXCEPT(find_mapped_region_bounds(&monmod_library_init, 
	                                        &monitor_start, &monitor_len),
		      exit(1));

	/* Sanity check that our linker script worked and, after loading,
	   the "unprotected" section is the very last page-aligned sub-section
	   of the loaded executable segment. */
	Z_TRY_EXCEPT(monitor_len == (monitor_len & ~(monmod_page_size-1))
	             && __unprotected_end == monitor_start + monitor_len
	             && (void *)__unprotected_start > monitor_start 
	             && (void *)__unprotected_start < monitor_start+monitor_len,
		     exit(1));
	protected_len = (void *)__unprotected_start - monitor_start;

	NZ_TRY_EXCEPT(monmod_init(monitor->env.pid, 
	                          monitor_start, 
	                          protected_len,
	                          &monmod_syscall_trusted_addr,
	                          &monmod_syscall_trace_enter),
	              exit(1));

#if VERBOSITY >= 1
	LZ_TRY_EXCEPT(gettimeofday(&monitor->start_tv, NULL),
	              exit(1));
	SAFE_LOGF("Starting monitored execution of process %d.\n",
	          monitor->env.pid);
#endif

	return 0;
}

int
__attribute__((section("unprotected")))
monitor_destroy(struct monitor *monitor)
{
	monitor->is_exiting = true;
	unprotected_funcs.exit(0);  /* any system call that gets us into
	                               monmod_handle_syscall will do here. */
}

static void terminate(struct monitor * const monitor)
{
	struct timeval end_tv, duration;
	replication_destroy(monitor);
	comm_destroy(&monitor->comm);
#if VERBOSITY >= 1
	SAFE_NZ_TRY(gettimeofday(&end_tv, NULL));
	timersub(&end_tv, &start_tv, &duration);
	SAFE_LOGF("Terminated after %ld.%06ld seconds.\n",
	          duration.tv_sec, duration.tv_usec);
#endif
	close(monmod_log_fd);
	/* Nothing may run after our monitor is destroyed. Without this,
	   exit code may flush buffers etc without us monitoring this.
	   FIXME always exits with zero exit code */
	exit(0);
}


/* ************************************************************************** *
 * System Call Monitoring                                                     *
 * ************************************************************************** */

/* All monitored system calls go through this function, registered with the
   monmod_init system call. */
long monmod_handle_syscall(struct syscall_trace_func_stack *stack)
{
	return monitor_handle_syscall(&monitor, stack);
}

long monitor_handle_syscall(struct monitor * const monitor,
                            struct syscall_trace_func_stack * const stack)
{
#if MEASURE_TRACING_OVERHEAD
	return monmod_trusted_syscall(SYSCALL_NO_REG(&stack->regs), 
           SYSCALL_ARG0_REG(&stack->regs), SYSCALL_ARG1_REG(&stack->regs), 
           SYSCALL_ARG2_REG(&stack->regs), SYSCALL_ARG3_REG(&stack->regs), 
           SYSCALL_ARG4_REG(&stack->regs), SYSCALL_ARG5_REG(&stack->regs));
#endif

	if(monitor->is_exiting) {
		terminate(monitor);
	}

	int s = 0;
	struct pt_regs *regs = &(stack->regs);
	const long syscall_no = SYSCALL_NO_REG(regs);
	const void *ret_addr = (void *)PC_REG(regs);
	struct syscall_handler const * const handler = get_handler(syscall_no);
	struct syscall_info actual = {};
	struct syscall_info canonical = {};
	void *handler_scratch_space = NULL;
	int dispatch = 0;
#if VERBOSITY >= 2
	struct timeval tv, rel_tv;
#endif

#if ENABLE_CHECKPOINTING
	restore_checkpoint_if_needed(&checkpoint_env, conf.restore_interval);
#endif
#if NO_HANDLER_TERMINATES
	if(NULL == handler) {
		SAFE_WARNF("No handler for system call %ld.\n", syscall_no);
		exit(1);
	}
#endif

	/* Preparation: Initialize data structures. */
	actual.no = syscall_no;
	SYSCALL_ARGS_TO_ARRAY(regs, actual.args);
	actual.ret = -ENOSYS;
	canonical.no = syscall_no;
	if(NULL != handler) {
		canonical.no = handler->canonical_no;
	}
	SYSCALL_ARGS_TO_ARRAY(regs, canonical.args);  
		// will probably be modified

	/* Phase 1: Determine call dispatch type through entry handler. */
#if VERBOSITY >= 2
	if(NULL != handler) {
		SAFE_LZ_TRY(gettimeofday(&tv, NULL));
		timersub(&tv, &start_tv, &rel_tv);
		SAFE_LOGF("[%3ld.%06ld] >> %s (%ld) -- enter from PC %p, PID "
			  "%d.\n", rel_tv.tv_sec, rel_tv.tv_usec,
			  handler->name, actual.no, ret_addr, getpid());
	}
#endif
	dispatch = DISPATCH_UNCHECKED | DISPATCH_EVERYONE;	
	if(NULL != handler && NULL != handler->enter) {
		dispatch = handler->enter(&monitor->env, handler, &actual, 
		                          &canonical, &handler_scratch_space);
	}
	if(policy_is_exempt(monitor->policy, &canonical, &monitor->env)) {
#if VERBOSITY >= 3
		SAFE_LOGF("Policy \"%s\" exempted system call from "
		          "cross-checking.\n", monitor->policy->name);
#endif
		dispatch &= ~DISPATCH_CHECKED & ~DISPATCH_DEFERRED_CHECK;
		dispatch |= DISPATCH_UNCHECKED;
	}
	syscall_check_dispatch_sanity(dispatch, handler, &actual, &canonical);

	/* Phase 2: Cross-check system call & arguments with other variants. */
	if(dispatch & (DISPATCH_CHECKED | DISPATCH_DEFERRED_CHECK)) {
		SAFE_LZ_TRY(s = cross_check_args(monitor, &canonical));
		if(0 == s) {
			syscall_handle_divergence(handler, &actual, &canonical);
		}
	}

	/* Phase 3: Execute system call locally if needed. */
	if(dispatch & DISPATCH_EVERYONE || 
	   ((dispatch & DISPATCH_LEADER) && monitor->is_leader)) {
		syscall_execute_locally(handler, &actual, &canonical);
		if(NULL != handler && NULL != handler->post_call) {
			/* This callback gets called whenever a system call has
			   actually been issued locally. It can be used to
			   normalize results in a canonical form before 
			   replication, from actual into canonical. */
			handler->post_call(&monitor->env, handler, dispatch, 
			                   &actual, &canonical, 
					   &handler_scratch_space);
		}
	}

	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
#if VERBOSITY >= 4
		if(monitor->is_leader) {
			SAFE_LOG("Appending replication information to "
			         "batch.\n");
		} else {
			SAFE_LOG("Awaiting replication information from "
			         "leader.\n");
		}
#endif
		/* Replicates contents of canonical.ret and canonical.args to 
		   be the same across all nodes. It is the exit handler's 
		   responsibility to copy this back to the actual results as
		   approriate. By default, actual.ret = canonical.ret will be
		   copied. */
		SAFE_NZ_TRY(replicate_results(monitor, &canonical));
		actual.ret = canonical.ret;
	}

	/* Phase 4: Run exit handlers, potentially denormalizing results. */
	if(NULL != handler && NULL != handler->exit 
	   && !(dispatch & DISPATCH_SKIP)) {
		handler->exit(&monitor->env, handler, dispatch, &actual, 
		              &canonical, &handler_scratch_space);
	}

#if VERBOSITY >= 2
	SAFE_LZ_TRY(gettimeofday(&tv, NULL));
	timersub(&tv, &start_tv, &rel_tv);
	SAFE_LOGF("[%3ld.%06ld] << Return %ld.\n\n", rel_tv.tv_sec, 
	          rel_tv.tv_usec, actual.ret);
#endif

	return actual.ret;
}

static int
syscall_check_dispatch_sanity(int dispatch,
                              struct syscall_handler const *const handler,
                              struct syscall_info *actual,
                              struct syscall_info *canonical)
{
	if(dispatch & DISPATCH_ERROR) {
		SAFE_WARN("Error on dispatch.\n");
		monmod_exit(1);
	}

	if(dispatch & DISPATCH_LEADER) {
		if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
#if VERBOSITY >= 2
			SAFE_WARN("Warning: Syscall dispatched only on leader, "
			          "but no replication flag set.\n"); 
#endif
			return 1;
		}
		if(!(canonical->ret_flags & ARG_FLAG_REPLICATE)) {
#if VERBOSITY >= 2
			SAFE_WARN("Warning: Syscall dispatched only on leader, "
			          "but no replication flag set for return "
				  "value. This is probably not what you "
				  "want.\n");
#endif
			return 1;
		}
	}

#if VERBOSITY >= 4
	if(NULL != handler) {
		syscall_log_buf[0] = '\0';
		log_args(syscall_log_buf, sizeof(syscall_log_buf), actual, 
		         canonical);
		SAFE_LOGF_LEN(sizeof(syscall_log_buf), "%s", 
		              syscall_log_buf);
	}
#endif

	return 0;
}

static
void syscall_handle_divergence(struct syscall_handler const *const handler,
                               struct syscall_info *actual,
                               struct syscall_info *canonical)
{
	int s;
#if !ENABLE_CHECKPOINTING
	SAFE_LOG("Divergence -- abort!\n");
#else
	SAFE_LOG("Divergence -- attempt restore last checkpoint.\n");
#endif
#if VERBOSITY > 0 && VERBOSITY < 3
	// Print divergence information if we have not before.
	if(NULL != handler) {
		SAFE_LOGF("%s (%ld)\n", handler->name, actual->no);
		char log_buf[1024];
		log_buf[0] = '\0';
		log_args(log_buf, sizeof(log_buf), actual, canonical);
		SAFE_LOGF_LEN(sizeof(log_buf), "%s", log_buf);
	}
#endif
#if ENABLE_CHECKPOINTING
	if(checkpoint_env.last_checkpoint.valid) {
		s = restore_last_checkpoint(&checkpoint_env);
		if(0 != s) {
			SAFE_WARNF("Checkpoint restoration failed with "
			          "exit code %d.\n", s);
		}
	} else {
		SAFE_WARN("No valid last checkpoint.\n");
	}
#endif
	monmod_exit(2);
}

static void syscall_execute_locally(struct syscall_handler const *const handler,
                                    struct syscall_info *actual, 
                                    struct syscall_info *canonical)
{
#if VERBOSITY >= 4
	SAFE_LOGF("Executing syscall no. %ld with (%ld, %ld, %ld, %ld, "
	          "%ld, %ld)\n",
		  actual->no, actual->args[0], actual->args[1],
		  actual->args[2], actual->args[3], actual->args[4],
		  actual->args[5]);
#endif
	actual->ret = monmod_trusted_syscall(actual->no, 
	                                     actual->args[0], 
	                                     actual->args[1],
	                                     actual->args[2],
	                                     actual->args[3],
	                                     actual->args[4], 
	                                     actual->args[5]);
	canonical->ret = actual->ret;  // Default to the same

#if VERBOSITY >= 4
		if(-1024 < actual->ret && actual->ret < 0) {
			SAFE_LOGF("Returned: %ld (potential errno: %s)\n", 
			          actual->ret, strerror(-actual->ret));
		} else {
			SAFE_LOGF("Returned: %ld\n", actual->ret);
		}
#endif
}
