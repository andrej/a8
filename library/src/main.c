#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#include "arch.h"
#include "syscall.h"
#include "util.h"
#include "config.h"
#include "communication.h"
#include "build_config.h"
#include "syscall.h"
#include "syscall_trace_func.h"
#include "handlers.h"
#include "environment.h"
#include "serialization.h"
#include "replication.h"
#include "custom_syscalls.h"
#include "init.h"
#include "unprotected.h"
#include "checkpointing.h"
#include "globals.h"

struct config conf;
int own_id;
struct communicator comm;
struct environment env;
#if ENABLE_CHECKPOINTING
struct checkpoint_env checkpoint_env = {};
#endif

struct variant_config *own_variant_conf;
int is_leader;
bool kernel_monmod_active = false;
int log_fd = 0;
size_t syscall_count = 0;

/* The following two are defined in the main.lds linker script and capture the
   start and end address of any functions marked section("unprotected").
   Functions in this section will remain accessible even when the rest of the
   monitor is memory-protected. */
void __unprotected_start();
void __unprotected_end();


long monmod_handle_syscall(struct syscall_trace_func_stack *stack)
{

	int s = 0;
	struct pt_regs *regs = &(stack->regs);
	const long syscall_no = SYSCALL_NO_REG(regs);
	const void *ret_addr = (void *)PC_REG(regs);
	struct syscall_handler const *handler = NULL;
	struct syscall_info actual = {};
	struct syscall_info canonical = {};
	void *handler_scratch_space = NULL;
	int dispatch = 0;

	syscall_count++;

	/* Find syscall handlers handler. */
	handler = get_handler(syscall_no);
	if(NULL == handler) {
		SAFE_LOGF(log_fd, "%ld -- no handler (PID %d)!\n", syscall_no, 
		          getpid());
#if NO_HANDLER_TERMINATES
		exit(1);
#endif
	}

	/* Preparation: Initialize data. */
	actual.no = syscall_no;
	SYSCALL_ARGS_TO_ARRAY(regs, actual.args);

#if MEASURE_TRACING_OVERHEAD
	return monmod_trusted_syscall(actual.no, actual.args[0], actual.args[1],
		                      actual.args[2], actual.args[3], 
				      actual.args[4], actual.args[5]);
#endif

	actual.ret = -ENOSYS;
	if(NULL != handler) {
		canonical.no = handler->canonical_no;
	} else {
		canonical.no = actual.no;
	}
	memcpy(canonical.args, actual.args, sizeof(actual.args));

#if ENABLE_CHECKPOINTING
	/* Periodically restore to the last checkpoint, as set in
	   config.restore_interval. This is used to assess the performance of
	   the checkpoint/restore mechanism. Otherwise, a restore only takes
	   place upon a divergence. */
	if(checkpoint_env.n_breakpoints > 0 &&
	   conf.restore_interval > 0 && checkpoint_env.last_checkpoint.valid) {
		if(checkpoint_env.breakpoints[0].hits 
		   % conf.restore_interval == 0) {
			SAFE_LOGF(log_fd, "<%d> Restoring last checkpoint.\n", 
			          getpid());
			restore_last_checkpoint(&checkpoint_env);
			/* Should be unreachable. */
			Z_TRY_EXCEPT(0,
			             exit(1));
		}
	}
#endif

	/* Phase 1: Cross-check arguments. */
#if VERBOSITY >= 2
	if(NULL != handler) {
		SAFE_LOGF(log_fd, ">> %s (%ld) -- enter from PC %p, PID %d.\n",
			  handler->name, actual.no, ret_addr, getpid());
	}
#endif
	if(NULL != handler && NULL != handler->enter) {
		dispatch = handler->enter(&env, handler, &actual, &canonical,
		                          &handler_scratch_space);
	} else {
		dispatch = DISPATCH_UNCHECKED | DISPATCH_EVERYONE;	
	}

#if VERBOSITY >= 3
	if(NULL != handler) {
		char log_buf[1024];
		log_buf[0] = '\0';
		log_args(log_buf, sizeof(log_buf), &actual, &canonical);
		SAFE_LOGF_LEN(sizeof(log_buf), log_fd, "%s", log_buf);
	}
#endif

	if(dispatch & DISPATCH_ERROR) {
		SAFE_LOGF(log_fd, "Error on dispatch.%s", "\n");
		monmod_exit(1);
	} else if(dispatch & (DISPATCH_CHECKED | DISPATCH_DEFERRED_CHECK)) {
		s = cross_check_args(&env, &canonical);
		if(0 == s) {
#if !ENABLE_CHECKPOINTING
			SAFE_LOGF(log_fd, "Divergence -- abort!%s", "\n");
#else
			SAFE_LOGF(log_fd, "Divergence -- attempt restore last "
			          "checkpoint.%s", "\n");
#endif
#if VERBOSITY > 0 && VERBOSITY < 3
			// Print divergence information if we have not before.
			if(NULL != handler) {
				SAFE_LOGF(log_fd, "%s (%ld) -- enter from "
				          "%p.\n", handler->name, actual.no, 
					  ret_addr);
				char log_buf[1024];
				log_buf[0] = '\0';
				log_args(log_buf, sizeof(log_buf), &actual, 
				         &canonical);
				SAFE_LOGF_LEN(sizeof(log_buf), log_fd, "%s", 
				              log_buf);
			}
#endif
#if ENABLE_CHECKPOINTING
			if(checkpoint_env.last_checkpoint.valid) {
				s = restore_last_checkpoint(&checkpoint_env);
				if(0 != s) {
					SAFE_LOGF(log_fd, "Checkpoint "
					          "restoration failed with exit"
						  "code %d.\n", s);
				}
			} else {
				SAFE_LOGF(log_fd, "No valid last checkpoint.%s",
				          "\n");
			}
#endif
			monmod_exit(1);
		} else if(0 > s) {
			SAFE_LOGF(log_fd, "Argument cross-checking failed%s",
			          "\n");
			monmod_exit(1);
		}
	}

	/* Phase 2: Execute system call locally if needed. */
	if(dispatch & DISPATCH_EVERYONE || 
	   ((dispatch & DISPATCH_LEADER) && is_leader)) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "Executing syscall no. %ld with ("
		          "%ld, %ld, %ld, %ld, %ld, %ld)\n",
			   actual.no, actual.args[0], actual.args[1],
			   actual.args[2], actual.args[3], actual.args[4],
			   actual.args[5]);
#endif
		actual.ret = monmod_trusted_syscall(actual.no, 
		                                    actual.args[0], 
		                                    actual.args[1],
		                                    actual.args[2],
		                                    actual.args[3],
		                                    actual.args[4], 
		                                    actual.args[5]);
		canonical.ret = actual.ret;  // Default to the same
		if(NULL != handler && NULL != handler->post_call) {
			/* This callback gets called whenever a system call has
			   actually been issued locally. It can be used to
			   normalize results in a canonical form before 
			   replication, from actual into canonical. */
			handler->post_call(&env, handler, dispatch, &actual, 
			                   &canonical, &handler_scratch_space);
		}

#if VERBOSITY >= 3
		if(-1024 < actual.ret && actual.ret < 0) {
			SAFE_LOGF(log_fd, "Returned: %ld (potential errno: %s)"
			          "\n", actual.ret, strerror(-actual.ret));
		} else {
			SAFE_LOGF(log_fd, "Returned: %ld\n", actual.ret);
		}
#endif
	}

	/* Phase 3: Replicate results if needed */
#if VERBOSITY >= 2
	if(dispatch & DISPATCH_LEADER) {
		if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
			SAFE_LOGF(log_fd,
				  "Warning: Syscall dispatched only on leader, "
			          "but no replication flag set.%s", "\n"); 
		}
		if(!(canonical.ret_flags & ARG_FLAG_REPLICATE)) {
			SAFE_LOGF(log_fd,
				  "Warning: Syscall dispatched only on leader, "
			          "but no replication flag set for return "
				  "value. This is probably not what you want."
				  "%s", "\n");
		}
	}
#endif
	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "Replicating results.%s", "\n");
#endif
		/* Replicates contents of canonical.ret and canonical.args to 
		   be the same across all nodes. It is the exit handler's 
		   responsibility to copy this back to the actual results as
		   approriate. By default, actual.ret = canonical.ret will be
		   copied. */
		NZ_TRY_EXCEPT(replicate_results(&env, &canonical),
			      monmod_exit(1));
		actual.ret = canonical.ret;
	}

	/* Phase 4: Run exit handlers, potentially denormalizing results. */
	if(NULL != handler && NULL != handler->exit 
	   && !(dispatch & DISPATCH_SKIP)) {
		handler->exit(&env, handler, dispatch, &actual, &canonical,
		              &handler_scratch_space);
	}

#if VERBOSITY >= 2
	SAFE_LOGF(log_fd, "<< Return %ld.\n\n", actual.ret);
#endif

	return actual.ret;
}


#pragma GCC push_options // Save current options
#pragma GCC optimize ("no-optimize-sibling-calls")
void monmod_library_init()
{
	pid_t own_pid = 0;
	const char *config_path, *own_id_str;
	char log_file_path[128];
	char tmp_path[128];
	struct variant_config *own_variant_config;
	void *monitor_start = NULL;
	size_t monitor_len = 0, protected_len = 0;

	page_size = sysconf(_SC_PAGE_SIZE);
	own_pid = getpid();
	
	/* Find the pages this module is loaded on. These pages will be 
	   protected by the kernel to remain inaccessible for other parts of
	   the program. */
	NZ_TRY_EXCEPT(find_mapped_region_bounds(&monmod_library_init, 
	                                        &monitor_start, &monitor_len),
		      exit(1));

	/* Sanity check that our linker script worked and, after loading,
	   the "unprotected" section is the very last page-aligned sub-section
	   of the loaded executable segment. */
	Z_TRY_EXCEPT(monitor_len == (monitor_len & ~(page_size-1))
	             && __unprotected_end == monitor_start + monitor_len
	             && (void *)__unprotected_start > monitor_start 
	             && (void *)__unprotected_start < monitor_start+monitor_len,
		     exit(1));
	protected_len = (void *)__unprotected_start - monitor_start;

	init_unprotected();

#if MEASURE_TRACING_OVERHEAD
	/* If we are only interested in measuring the tracing overhead, register
	   the monitor now and exit, before settin up any of the network
	   connections or checkpointing environment. */
	NZ_TRY_EXCEPT(monmod_init(own_pid, 
	                          monitor_start, 
	                          protected_len,
	                          &monmod_syscall_trusted_addr,
	                          &monmod_syscall_trace_enter),
	              exit(1));
	return;
#endif

	/* Read environment variables. */
	if(NULL == (own_id_str = getenv("MONMOD_ID"))) {
		WARN("libmonmod.so requres MONMOD_ID environment variable. \n");
		exit(1);
	}
	if(NULL == (config_path = getenv("MONMOD_CONFIG"))) {
		WARN("libmonmod.so requires MONMOD_CONFIG environment variable "
		     "to point to a valid configuration file.\n");
		exit(1);
	}
	errno = 0;
	own_id = strtoll(own_id_str, NULL, 10);
	if(0 != errno) {
		WARN("invalid MONMOD_ID\n");
		exit(1);
	}

	/* Open log file. */
	snprintf(log_file_path, sizeof(log_file_path), MONMOD_LOG_FILE,
	         own_id);
	if(0 > (log_fd = open(log_file_path, O_WRONLY | O_APPEND | O_CREAT 
	                                     | O_TRUNC, 
	                      0664)))
	{
		WARNF("unable to open log file at %s: %s\n",
		      MONMOD_LOG_FILE,
		      strerror(errno));
		exit(1);
	}

	/* Parse configuration. */
	NZ_TRY_EXCEPT(parse_config(config_path, &conf), exit(1));
	Z_TRY_EXCEPT(own_variant_conf = get_variant(&conf, own_id), exit(1));
	is_leader = conf.leader_id == own_id;

	/* The checkpointing environment needs to be initialized before 
	   the monitor is registered: CRIU checkpointing forks a new
	   dumper/restorer parent process, and the child process is the one
	   that should register to be monitored. */
#if ENABLE_CHECKPOINTING
	NZ_TRY_EXCEPT(init_checkpoint_env(&checkpoint_env,
	                                  own_variant_conf,
					  monitor_start, protected_len),
	              exit(1));
	own_pid = getpid();
#endif

	/* Issue monmod_init system call. */
	NZ_TRY_EXCEPT(monmod_init(own_pid, 
	                          monitor_start, 
	                          protected_len,
	                          &monmod_syscall_trusted_addr,
	                          &monmod_syscall_trace_enter),
	              exit(1));

	// Connect all nodes.
	NZ_TRY_EXCEPT(comm_init(&comm, own_id, &own_variant_conf->addr), 
	              exit(1));
	for(size_t i = 0; i < conf.n_variants; i++) {
		if(conf.variants[i].id == own_id) {
			continue;
		}
		NZ_TRY_EXCEPT(comm_connect(&comm, conf.variants[i].id, 
		                           &conf.variants[i].addr),
		              exit(1));
	}

	env_init(&env, &comm, &conf, own_id);
	
	/* The architecture-specific caller of this code issues a
	   monmod_reprotect call to initialize the module and protect the
	   module code after this and exits out of it. */
}
#pragma GCC pop_options

void 
__attribute__((destructor)) 
__attribute__((section("unprotected")))
destruct()
{
	/* Currently, the destructor is called while the monitor's pages are
	   protected, so we are restricted to only calling unprotected
	   functions here. */

	unprotected_funcs.close(log_fd);

	// Close shared memory area.
	// comm_destroy(&comm);

	/* Nothing may run after our monitor is destroyed. Without this,
	   exit code may flush buffers etc without us monitoring this.
	   FIXME always exits with zero exit code */
	unprotected_funcs.exit(0);
}
