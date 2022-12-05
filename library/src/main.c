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

#define __NR_monmod_toggle (__NR_syscalls+2)

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

long trusted_area(struct syscall_trace_func_args *raw_args)
{
	/* Disable system call monitoring for any syscalls issued from the 
	   monitor code. */
	if(0 != monmod_toggle(false)) {
		SAFE_LOGF(log_fd, "unable to disable monitoring.%s", "\n");
		monmod_exit(1);
	}

	long ret = 0;
	struct pt_regs *regs = &(raw_args->regs);
	struct syscall_handler const * handler = NULL;
	int dispatch = 0;
	char buf[128];
	size_t buf_len = sizeof(buf);
	long no, args[7];

	/* Preparation: Initialize data. */
	no = SYSCALL_NO_REG(regs);
	args[0] = SYSCALL_ARG0_REG(regs);
	args[1] = SYSCALL_ARG1_REG(regs);
	args[2] = SYSCALL_ARG2_REG(regs);
	args[3] = SYSCALL_ARG3_REG(regs);
	args[4] = SYSCALL_ARG4_REG(regs);
	args[5] = SYSCALL_ARG5_REG(regs);

	/* Phase 1: Find entry handler and cross-check arguments. */
	handler = get_handler(SYSCALL_NO_REG(regs));
	if(NULL != handler && NULL != handler->enter) {
		SAFE_LOGF(log_fd, "%s (%ld/%ld) -- enter from %p.\n",
		          handler->name, SYSCALL_NO_REG(regs), 
		          handler->canonical_no, raw_args->call_site);
		dispatch = handler->enter(&env, &no, args, &buf_len, buf);
	} else {
		SAFE_LOGF(log_fd, "%ld -- enter with no handler!\n",
		          SYSCALL_NO_REG(regs));
		dispatch = DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	if(!(dispatch & (DISPATCH_EVERYONE | DISPATCH_LEADER)) ||
	   !(dispatch & (DISPATCH_UNCHECKED | DISPATCH_CHECKED 
	                 | DISPATCH_DEFERRED_CHECK))) {
		SAFE_LOGF(log_fd, "invalid dispatch returned from enter.%s", 
		          "\n");
		monmod_exit(1);
	}
	if(dispatch & DISPATCH_CHECKED) {
		if(buf == NULL) {
			SAFE_LOGF(log_fd, "handler did not return buffer.%s",
			          "\n");
			monmod_exit(1);
		}
#if CHECK_HASHES_ONLY
		unsigned long hash = sdbm_hash(buf_len, buf);
		buf_len = sizeof(hash);
		memcpy(buf, (void *)&hash, buf_len);
#endif
		if(!comm_all_agree(&comm, conf.leader_id, buf_len, buf)) {
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

	if(NULL != handler) {
		SAFE_LOGF(log_fd, "%s (%ld/%ld) -- exit with %ld.\n",
		          handler->name, SYSCALL_NO_REG(regs), 
			  handler->canonical_no, ret);
	} else {
		SAFE_LOGF(log_fd, "%ld -- exit with %ld.\n", 
		          SYSCALL_NO_REG(regs), ret);
	}

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
	
	long traced_syscalls[] = {
		__NR_write,
		__NR_writev,
		__NR_pwritev,
		__NR_pwrite64,
		__NR_epoll_wait,
		__NR_epoll_pwait,
		__NR_epoll_ctl,
		__NR_nanosleep,
		__NR_sendfile
	};
	const long n_traced_syscalls = sizeof(traced_syscalls)
	                               / sizeof(traced_syscalls[0]);

	// Get ID from environment variable.
	if(NULL == (own_id_str = getenv("MONMOD_ID"))) {
		WARN("libmonmod.so requres MONMOD_ID environment variable. \n");
		return;
	}
	if(NULL == (config_path = getenv("MONMOD_CONFIG"))) {
		WARN("libmonmod.so requires MONMOD_CONFIG environment variable "
		     "to point to a valid configuration file.\n");
		return;
	}
	errno = 0;
	own_id = strtoll(own_id_str, NULL, 10);
	if(0 != errno) {
		WARN("invalid MONMOD_ID\n");
		return;
	}

	// Open log file.
	snprintf(log_file_path, sizeof(log_file_path), MONMOD_LOG_FILE,
	         own_id);
	if(0 > (log_fd = open(log_file_path, O_WRONLY | O_APPEND | O_CREAT)))
	{
		WARNF("unable to open log file at %s: %s\n",
		      MONMOD_LOG_FILE,
		      strerror(errno));
		return;
	}

	// Read envirnoment variables.

	// Parse configuration.
	NZ_TRY_EXCEPT(parse_config(config_path, &conf), return);
	Z_TRY_EXCEPT(own_variant_conf = get_variant(own_id), return);
	is_leader = conf.leader_id == own_id;

	// Connect all nodes.
	NZ_TRY_EXCEPT(comm_init(&comm, own_id, &own_variant_conf->addr), 
	              return);
	for(size_t i = 0; i < conf.n_variants; i++) {
		if(conf.variants[i].id == own_id) {
			continue;
		}
		NZ_TRY_EXCEPT(comm_connect(&comm, conf.variants[i].id, 
		                           &conf.variants[i].addr),
			      return);
	}

	// Set up system call tracking with kernel module
	if(0 != write_monmod_config_long(MONMOD_SYSFS_PATH
	                                 MONMOD_SYSFS_TRACEE_PIDS_FILE,
	                                 own_pid)) {
		WARNF("unable to write own process ID to %s. Is monmod kernel"
		      "module loaded?\n", tmp_path);
		return;
	}

	snprintf(tmp_path, sizeof(tmp_path), MONMOD_SYSFS_PATH 
	         MONMOD_SYSFS_TRUSTED_ADDR_FILE, own_pid);
	if(0 != write_monmod_config_long(tmp_path,
					 (long)&monmod_syscall_trusted_addr)) {
		WARNF("unable to write address %p to %s.\n",
		      &monmod_syscall_trusted_addr,
		      tmp_path);
		return;
	}

	snprintf(tmp_path, sizeof(tmp_path), MONMOD_SYSFS_PATH 
	         MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE, own_pid);
	if(0 != write_monmod_config_long(tmp_path,
					 (long)&syscall_trace_func)) {
		WARNF("unable to write address %p to %s.\n",
		      &syscall_trace_func,
		      tmp_path);
		return;
	}

	// FIXME FIXME
	if(0 != write_monmod_config_longs(MONMOD_SYSFS_PATH
	                                  MONMOD_SYSFS_TRACED_SYSCALLS_FILE,
					  n_traced_syscalls,
					  traced_syscalls)) {
		WARN("unable to write traced syscalls.\n");
		return;
	}


	if(0 != monmod_toggle(true)) {
		WARN("Unable to activate monitoring.\n");
		monmod_exit(1);
	}

	/*
	// Tests
	const char hello[] = "Hello, World.\n";
	char recvbuf[sizeof(hello)];
	if(own_id == 0) {
		printf("Sending %s.\n", hello);
		comm_broadcast_p(&comm, hello);
	} else {
		printf("Receiving.\n");
		comm_receive_p(&comm, 0, &recvbuf);
		printf("Received %s\n", recvbuf);
	}*/
}

void __attribute__((destructor)) destruct()
{
	
	if(0 != monmod_toggle(false)) {
		WARN("Unable to deactivate monitoring on exit.\n");
	}

	close(log_fd);

	// Close shared memory area.
	//comm_destroy(&comm);
}
