#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdbool.h>
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

#define __NR_monmod_toggle (MAX_SYSCALL_NO+2)

#define SAFE_LOGF_LEN(n, log_fd, msg, ...) { \
	char log[n]; \
	int len = 0; \
	len = snprintf(log, sizeof(log), \
	              msg, __VA_ARGS__); \
	if(0 < len && len < sizeof(log)) { \
		monmod_trusted_syscall(__NR_write, log_fd, (long)log, \
		                       (long)len, 0, 0, 0); \
	} \
}
#define SAFE_LOGF(log_fd, msg, ...) SAFE_LOGF_LEN(128, log_fd, msg, __VA_ARGS__)

struct config conf;
int own_id;
struct communicator comm;
struct environment env;
int log_fd = 0;

/* The following two are for convenience but do not add any information beyond
   what is in the above global vars. */
struct variant_config *own_variant_conf;
int is_leader;
bool kernel_monmod_active = false;

int monmod_exit(int code)
{
	comm_destroy(&comm);
	return monmod_trusted_syscall(__NR_exit, code, 0, 0, 0, 0, 0);
}

int monmod_toggle(bool onoff)
{
	int ret = monmod_trusted_syscall(__NR_monmod_toggle, onoff,  
	                                 0, 0, 0, 0, 0);
	if(ret & 1 != 1) {
		SAFE_LOGF(log_fd, "monmod_toggle unsuccessfully returned with "
		          "%x\n", ret);
		return 1;
	}
	if(ret >> 1 != onoff) {
		return 2;
	}
	return 0;
}

long monmod_syscall_handle(struct syscall_trace_func_args *raw_args)
{
	/* Disable system call monitoring for any syscalls issued from the 
	   monitor code. */
	if(0 != monmod_toggle(false)) {
		SAFE_LOGF(log_fd, "unable to disable monitoring.%s", "\n");
		monmod_exit(1);
	}

	int s = 0;
	struct user_regs_struct *regs = &(raw_args->regs);
	struct syscall_handler const *handler = NULL;
	struct syscall_info actual = {};
	struct syscall_info canonical = {};
	void *handler_scratch_space;
	int dispatch = 0;

	/* Find syscall handlers handler. */
	handler = get_handler(raw_args->syscall_no);
	if(NULL == handler) {
		SAFE_LOGF(log_fd, "%ld -- no handler!\n",
		          raw_args->syscall_no);
	}

	/* Preparation: Initialize data. */
	actual.no = raw_args->syscall_no;
	SYSCALL_ARGS_TO_ARRAY(regs, actual.args);
	actual.ret = -ENOSYS;
	if(NULL != handler) {
		canonical.no = handler->canonical_no;
	} else {
		canonical.no = actual.no;
	}
	memcpy(canonical.args, actual.args, sizeof(actual.args));

	/* Phase 1: Cross-check arguments. */
#if VERBOSITY >= 2
	if(NULL != handler) {
		SAFE_LOGF(log_fd, "%s (%ld) -- enter from %p.\n",
			  handler->name, actual.no, raw_args->ret_addr);
	}
#endif
	if(NULL != handler && NULL != handler->enter) {
		dispatch = handler->enter(&env, handler, &actual, &canonical,
		                          &handler_scratch_space);
	} else {
		dispatch = DISPATCH_CHECKED | DISPATCH_EVERYONE;	
	}

#if VERBOSITY >= 3
	if(NULL != handler) {
		char log_buf[1024];
		log_buf[0] = '\0';
		log_args(log_buf, sizeof(log_buf), &canonical);
		SAFE_LOGF_LEN(sizeof(log_buf), log_fd, "%s", log_buf);
	}
#endif

	if(dispatch & DISPATCH_ERROR) {
		SAFE_LOGF(log_fd, "Error on dispatch.%s", "\n");
		monmod_exit(1);
	} else if(dispatch & (DISPATCH_CHECKED | DISPATCH_DEFERRED_CHECK)) {
		s = cross_check_args(&env, &canonical);
		if(0 == s) {
			SAFE_LOGF(log_fd, "Divergence -- abort!%s", "\n");
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
#if VERBOSITY >= 4
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
#if VERBOSITY >= 4
		SAFE_LOGF(log_fd, "Returned: %ld\n", actual.ret);
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
#if VERBOSITY >= 4
		SAFE_LOGF(log_fd, "Replicating results.%s", "\n");
#endif
		NZ_TRY_EXCEPT(replicate_results(&env, &actual, &canonical),
			      monmod_exit(1));
	}

	/* Phase 4: Run exit handlers, potentially denormalizing results. */
	if(NULL != handler && NULL != handler->exit 
	   && !(dispatch & DISPATCH_SKIP)) {
		handler->exit(&env, handler, dispatch, &actual, &canonical,
		              &handler_scratch_space);
	}

#if VERBOSITY >= 2
	if(NULL != handler) {
		SAFE_LOGF(log_fd, "%s (%ld) -- exit with %ld.\n\n",
		          handler->name, actual.no, actual.ret);
	}
#endif

	/* Re-enable syscall monitoring. */
	if(0 != monmod_toggle(true)) {
		SAFE_LOGF(log_fd, "unable to reactivate monitoring.%s", "\n");
		monmod_exit(1);
	}

	return actual.ret;
}

static int write_monmod_config(const char *path, const char *val, 
                                      size_t len)
{
	int f = open(path, O_WRONLY);
	if(-1 == f) {
		return 1;
	}
	if(len != write(f, val, len)) {
		close(f);
		return 1;
	}
	return 0;
}

static int write_monmod_config_long(const char *path, long val)
{
	char valstr[24];
	int valstr_len = snprintf(valstr, sizeof(valstr), "%ld\n", val);
	if(0 > valstr_len || valstr_len >= sizeof(valstr)) {
		return 1;
	}
	return write_monmod_config(path, valstr, valstr_len);
}

static int write_monmod_config_longs(const char *path, size_t n_longs,
                                     long *vals)
{
	const int max_val_len = 24;  // longmax takes 20 digits
	size_t valstr_max_len = max_val_len * n_longs;
	char valstr[valstr_max_len];
	int valstr_len = 0;
	for(size_t i = 0; i < n_longs; i++) {
		size_t this_valstr_max_len = max_val_len;
		if(8 > valstr_max_len - valstr_len) {
			this_valstr_max_len = valstr_max_len - valstr_len;
		}
		int this_valstr_len = 0;
		this_valstr_len = snprintf(valstr + valstr_len, 
		                           this_valstr_max_len,
		                           "%ld\n", vals[i]);
		if(0 > this_valstr_len 
		   || this_valstr_len >= this_valstr_max_len) {
			return 1;
		}
		valstr_len += this_valstr_len;
	}
	return write_monmod_config(path, valstr, valstr_len);
}

void __attribute__((constructor)) init()
{
	pid_t own_pid = 0;
	const char *config_path, *own_id_str;
	char log_file_path[128];
	char tmp_path[128];
	struct variant_config *own_variant_config;

	own_pid = getpid();
	
	long untraced_syscalls[] = { };
	const long n_untraced_syscalls = sizeof(untraced_syscalls)
	                               / sizeof(untraced_syscalls[0]);

	// Sanity check
	Z_TRY_EXCEPT(monmod_syscall_trusted_addr 
	             != monmod_syscall_untrusted_addr,
		     exit(1));

	// Read environment variables.
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

	// Open log file.
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

	// Parse configuration.
	NZ_TRY_EXCEPT(parse_config(config_path, &conf), exit(1));
	Z_TRY_EXCEPT(own_variant_conf = get_variant(&conf, own_id), exit(1));
	is_leader = conf.leader_id == own_id;

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

	// Set up system call tracking with kernel module
	if(0 != write_monmod_config_long(MONMOD_SYSFS_PATH
	                                 MONMOD_SYSFS_TRACEE_PIDS_FILE,
	                                 own_pid)) {
		WARNF("unable to write own process ID to %s. Is monmod kernel "
		      "module loaded?\n", 
		      MONMOD_SYSFS_PATH
		      MONMOD_SYSFS_TRACEE_PIDS_FILE);
		exit(1);
	}

	snprintf(tmp_path, sizeof(tmp_path), MONMOD_SYSFS_PATH 
	         MONMOD_SYSFS_TRUSTED_ADDR_FILE, own_pid);
	if(0 != write_monmod_config_long(tmp_path,
					 (long)&monmod_syscall_trusted_addr)) {
		WARNF("unable to write address %p to %s.\n",
		      &monmod_syscall_trusted_addr,
		      tmp_path);
		exit(1);
	}

	snprintf(tmp_path, sizeof(tmp_path), MONMOD_SYSFS_PATH 
	         MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE, own_pid);
	if(0 != write_monmod_config_long(tmp_path,
					 (long)&monmod_syscall_trace_enter)) {
		WARNF("unable to write address %p to %s.\n",
		      &monmod_syscall_trace_enter,
		      tmp_path);
		exit(1);
	}

	if(n_untraced_syscalls > 0) {
		if(0 != write_monmod_config_longs(MONMOD_SYSFS_PATH
					MONMOD_SYSFS_UNTRACED_SYSCALLS_FILE,
					n_untraced_syscalls,
					untraced_syscalls)) {
			WARN("unable to write traced syscalls.\n");
			exit(1);
		}
	}

	env_init(&env, &comm, &conf, own_id);

	if(0 != monmod_toggle(true)) {
		WARN("Unable to activate monitoring.\n");
		monmod_exit(1);
	}
}

void __attribute__((destructor)) destruct()
{
	
	if(0 != monmod_toggle(false)) {
		WARN("Unable to deactivate monitoring on exit.\n");
	}

	close(log_fd);


	// Close shared memory area.
	comm_destroy(&comm);

	/* Nothing may run after our monitor is destroyed. Without this,
	   exit code may flush buffers etc without us monitoring this.
	   FIXME always exits with zero exit code */
	monmod_trusted_syscall(__NR_exit, 0, 0, 0, 0, 0, 0);
}
