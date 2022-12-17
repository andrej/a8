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

#define __NR_monmod_toggle (MAX_SYSCALL_NO+2)

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
	return monmod_syscall(__NR_exit, code, 0, 0, 0, 0, 0);
}

int monmod_toggle(bool onoff)
{
	int ret = monmod_syscall(__NR_monmod_toggle, onoff, 0, 0, 0, 0, 0);
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

char *serialize_args(size_t *len, const struct syscall_handler *handler, 
                     long args[N_SYSCALL_ARGS])
{
	size_t n = 0;
	size_t written = 0;
	int n_args = 0;
	char *out = NULL;
#if VERBOSITY >= 3
	char log_buf[512] = {};
	size_t log_written = 0;
#endif
	struct arg_types arg_types = {};
	if(NULL != handler->get_arg_types) {
		arg_types = 
			handler->get_arg_types(&env, handler->arch_no, args);
	}
	/* If there is no get_arg_types() handler, arg_types is initialized to
	   all zeroes. Since IGNORED argument type maps to zero, this simply
	   ignores all arguments and serializes only the system call number. */
	for(int i = 0; i < N_SYSCALL_ARGS; i++) {
		if(IGNORE == arg_types.arg_types[i].kind) {
			continue;
		}
		n += get_serialized_size((const char *)&args[i], 
		                         &arg_types.arg_types[i]);
		n_args++;
	}
	n += sizeof(uint64_t); // For syscall no
	out = calloc(n, 1);
	memcpy(out, &handler->canonical_no, sizeof(uint64_t));
	written += sizeof(uint64_t);
	for(int i = 0; i < n_args; i++) {
		if(IGNORE == arg_types.arg_types[i].kind) {
			continue;
		}
		written += serialize_into((const char *)&args[i],
			                  &arg_types.arg_types[i],
			                  out + written);
#if VERBOSITY >= 3
		log_written += snprintf(log_buf + log_written,
		                        sizeof(log_buf) - log_written,
				        "  Argument %d:\n    ", i);
		log_written += log_str_of((const char *)&args[i],
		                          &arg_types.arg_types[i],
					  log_buf + log_written, 
					  sizeof(log_buf) - log_written);
		log_written += snprintf(log_buf + log_written,
		                        sizeof(log_buf) - log_written, "\n");
#endif
	}
#if VERBOSITY >= 3
	SAFE_LOGF_LEN(1024, log_fd, "%s", log_buf);
#endif
	if(NULL != handler->free_arg_types) {
		handler->free_arg_types(arg_types.arg_types);
	}
	*len = written;
	return out;
}

bool cross_check_arguments(const struct syscall_handler *handler, long args[7])
{
	bool ret = false;
	char *serialized_args_buf = NULL;
	size_t serialized_args_buf_len = 0;
	serialized_args_buf = serialize_args(&serialized_args_buf_len,
	                                     handler,
	                                     args);
	if(NULL == serialized_args_buf) {
		SAFE_LOGF(log_fd, "could not serialize args%s", "\n");
		return false;
	}
#if CHECK_HASHES_ONLY
	const unsigned long hash = sdbm_hash(serialized_args_buf_len,
						serialized_args_buf);
	free_and_null(serialized_args_buf);
	serialized_args_buf = malloc(sizeof(unsigned long));
	memcpy(serialized_args_buf, &hash, sizeof(hash));
	serialized_args_buf_len = sizeof(hash);
#endif
	ret = comm_all_agree(&comm, conf.leader_id,
	                     serialized_args_buf_len,
			     serialized_args_buf);
	free_and_null(serialized_args_buf);
	return ret;
}

long monmod_syscall_handle(struct syscall_trace_func_args *raw_args)
{
	/* Disable system call monitoring for any syscalls issued from the 
	   monitor code. */
	if(0 != monmod_toggle(false)) {
		SAFE_LOGF(log_fd, "unable to disable monitoring.%s", "\n");
		monmod_exit(1);
	}

	long ret = 0;
	struct user_regs_struct *regs = &(raw_args->regs);
	struct syscall_handler const *handler = NULL;
	int dispatch = 0;
	long no, args[N_SYSCALL_ARGS];

	/* Preparation: Initialize data. */
	no = raw_args->syscall_no;
	SYSCALL_ARGS_TO_ARRAY(regs, args);

	/* Phase 1: Find entry handler and cross-check arguments. */
	handler = get_handler(no);
	if(NULL != handler && NULL != handler->enter) {
#if VERBOSITY >= 2
		SAFE_LOGF(log_fd, "%s (%ld/%ld) -- enter from %p.\n",
		          handler->name, no, 
		          handler->canonical_no, raw_args->ret_addr);
#endif
		dispatch = handler->enter(&env, &no, args);
	} else {
#if VERBOSITY >= 2
		SAFE_LOGF(log_fd, "%ld -- enter with no handler!\n",
		          no);
#endif 
		dispatch = DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}

	if(dispatch & DISPATCH_ERROR) {
		SAFE_LOGF(log_fd, "error on dispatch.%s", "\n");
		monmod_exit(1);
	} else if(dispatch & DISPATCH_CHECKED) {
		if(false == cross_check_arguments(handler, args)) {
			SAFE_LOGF(log_fd, "divergence!%s", "\n");
			monmod_exit(1);
		}
	}

	/* Phase 2: Execute system call locally if needed. */
	if(dispatch & DISPATCH_EVERYONE || 
	   (dispatch & DISPATCH_LEADER && is_leader)) {
		ret = monmod_syscall(no, args[0], args[1], args[2], args[3],
		                     args[4], args[5]);
	} else {
		/* It is the exit handler's responsibility to replicate the
		   return value and overwrite the following. */
		ret = -ENOSYS;
	}

	/* Phase 3: Run exit handlers, potentially replicating results. */
	if(NULL != handler && NULL != handler->exit) {
		handler->exit(&env, no, args, &ret);
	}

#if VERBOSITY >= 2
	if(NULL != handler) {
		SAFE_LOGF(log_fd, "%s (%ld/%ld) -- exit with %ld.\n\n",
		          handler->name, no, 
			  handler->canonical_no, ret);
	} else {
		SAFE_LOGF(log_fd, "%ld -- exit with %ld.\n\n", 
		          no, ret);
	}
#endif

	/* Re-enable syscall monitoring. */
	if(0 != monmod_toggle(true)) {
		SAFE_LOGF(log_fd, "unable to reactivate monitoring.%s", "\n");
		monmod_exit(1);
	}

	return ret;
}

static inline struct variant_config *get_variant(int id)
{
	for(int i = 0; i < conf.n_variants; i++) {
		if(conf.variants[i].id == id) {
			return &conf.variants[i];
		}
	}
	return NULL;
}

static inline int write_monmod_config(const char *path, const char *val, 
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

static inline int write_monmod_config_long(const char *path, long val)
{
	char valstr[24];
	int valstr_len = snprintf(valstr, sizeof(valstr), "%ld\n", val);
	if(0 > valstr_len || valstr_len >= sizeof(valstr)) {
		return 1;
	}
	return write_monmod_config(path, valstr, valstr_len);
}

static inline int write_monmod_config_longs(const char *path, size_t n_longs,
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
	Z_TRY_EXCEPT(own_variant_conf = get_variant(own_id), exit(1));
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
	monmod_syscall(__NR_exit, 0, 0, 0, 0, 0, 0);
}
