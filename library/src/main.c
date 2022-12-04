#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdio.h>
#include "arch.h"
#include "syscall.h"
#include "util.h"
#include "config.h"
#include "communication.h"
#include "build_config.h"
#include "syscall_trace_func.h"

struct config conf;
int own_id;
struct communicator comm;

struct something {
	long a;
	long b;
	long c;
	long d;
};

long trusted_area(struct syscall_trace_func_args *args)
{
	char log[128];
	long ret = 0;
	int len = 0;
	struct pt_regs *regs = &(args->regs);

	len = snprintf(log, sizeof(log),
	              "Entering system call %ld, called from %p.\n",
		      SYSCALL_NO_REG(regs),
		      args->call_site);
	if(0 < len && len < sizeof(log)) {
		monmod_syscall(__NR_write, 0, (long)log, (long)len, 0, 0, 0);
	}

	ret = monmod_syscall(SYSCALL_NO_REG(regs),
	                     SYSCALL_ARG0_REG(regs), 
	                     SYSCALL_ARG1_REG(regs), 
	                     SYSCALL_ARG2_REG(regs), 
	                     SYSCALL_ARG3_REG(regs), 
	                     SYSCALL_ARG4_REG(regs),
	                     SYSCALL_ARG5_REG(regs));

	len = snprintf(log, sizeof(log),
	              "System call %ld returned %ld.\n",
		      SYSCALL_NO_REG(regs),
		      ret);
	if(0 < len && len < sizeof(log)) {
		monmod_syscall(__NR_write, 0, (long)log, (long)len, 0, 0, 0);
	}

	//PREPARE_RETURN_FROM_TRUSTED_AREA(sizeof(args));
	return ret;
	//return 0xF00BAF;
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
	char valstr[8];
	int valstr_len = snprintf(valstr, sizeof(valstr), "%ld\n", val);
	if(0 > valstr_len || valstr_len >= sizeof(valstr)) {
		return 1;
	}
	return write_monmod_config(path, valstr, valstr_len);
}

static inline int write_monmod_config_longs(const char *path, size_t n_longs,
                                            long *vals)
{
	const int max_val_len = 24;  // longmax takes 20 digits I think
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
	const char *config_path, *own_id_str;
	struct variant_config *own_variant_config;
	long trusted_area_bounds[2] = {
		(long)&syscall_trace_func,
		(long)&syscall_trace_func+32   // FIXME FIXME FIXME
	};
	long traced_syscalls[] = {
		__NR_write,
		__NR_nanosleep
	};
	const long n_traced_syscalls = sizeof(traced_syscalls)
	                               / sizeof(traced_syscalls[0]);

	if(0 != write_monmod_config_longs(MONMOD_SYSFS_PATH 
	                                  MONMOD_SYSFS_ADDR_FILE,
					  1,
					  trusted_area_bounds)) {
		WARNF("unable to write address %p to %s.\n",
		      (void *)trusted_area_bounds[0],
		      MONMOD_SYSFS_PATH MONMOD_SYSFS_ADDR_FILE);
		return;
	}

	if(0 != write_monmod_config_longs(MONMOD_SYSFS_PATH
	                                  MONMOD_SYSFS_TRACED_SYSCALLS_FILE,
					  n_traced_syscalls,
					  traced_syscalls)) {
		WARN("unable to write traced syscalls.\n");
		return;
	}

	if(0 != write_monmod_config_long(MONMOD_SYSFS_PATH 
	                                 MONMOD_SYSFS_PID_FILE,
	                                 getpid())) {
		WARNF("unable to write own process ID to %s. Is monmod kernel"
		      "module loaded?\n", 
		      MONMOD_SYSFS_PATH MONMOD_SYSFS_PID_FILE);
		return;
	}

	if(0 != write_monmod_config_long(MONMOD_SYSFS_PATH
	                                 MONMOD_SYSFS_ACTIVE_FILE,
					 1)) {
		WARN("Unable to activate monmod kernel module.\n");
		return;
	}
	// Read MONMOD_SMEM environment variable and set up shared memory area.

	// Read envirnoment variables.
	/*if(NULL == (config_path = getenv("MONMOD_CONFIG"))) {
		WARN("libmonmod.so requires MONMOD_CONFIG environment variable "
		     "to point to a valid configuration file.\n");
		return;
	}
	if(NULL == (own_id_str = getenv("MONMOD_ID"))) {
		WARN("libmonmod.so requres MONMOD_ID environment variable. \n");
		return;
	}
	errno = 0;
	own_id = strtoll(own_id_str, NULL, 10);
	if(0 != errno) {
		WARN("invalid MONMOD_ID\n");
		return;
	}

	// Parse configuration.
	NZ_TRY_EXCEPT(parse_config(config_path, &conf), return);
	Z_TRY_EXCEPT(own_variant_config = get_variant(own_id), return);

	// Connect all nodes.
	NZ_TRY_EXCEPT(comm_init(&comm, own_id, &own_variant_config->addr), 
	              return);
	for(size_t i = 0; i < conf.n_variants; i++) {
		if(conf.variants[i].id == own_id) {
			continue;
		}
		NZ_TRY_EXCEPT(comm_connect(&comm, conf.variants[i].id, 
		                           &conf.variants[i].addr),
			      return);
	}

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
	
	if(0 != write_monmod_config_long(MONMOD_SYSFS_PATH
	                                 MONMOD_SYSFS_ACTIVE_FILE,
					 0)) {
		WARN("Unable to deactivate monmod kernel module.\n");
		return;
	}
	// Close shared memory area.
	//comm_destroy(&comm);
}
