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
#include <sys/time.h>

#include "arch.h"
#include "syscall.h"
#include "util.h"
#include "config.h"
#include "communication.h"
#include "build_config.h"
#include "syscall.h"
#include "syscall_trace_func.h"
#include "environment.h"
#include "serialization.h"
#include "replication.h"
#include "custom_syscalls.h"
#include "library_init.h"
#include "unprotected.h"
#include "checkpointing.h"
#include "globals.h"
#include "monitor.h"


/* ************************************************************************** *
 * Globals                                                                    *
 * ************************************************************************** */

int monmod_log_fd = 0;
size_t monmod_page_size = 0;


/* ************************************************************************** *
 * Local variables                                                            *
 * ************************************************************************** */

#if ENABLE_CHECKPOINTING
struct checkpoint_env checkpoint_env = {};  // dumped checkpoints, ...
#endif

int own_id;
struct variant_config *own_variant_conf;


/* ************************************************************************** *
 *  Initialization                                                            *
 * ************************************************************************** */

#pragma GCC push_options // Save current options
#pragma GCC optimize ("no-optimize-sibling-calls")
void monmod_library_init()
{
	struct config conf = {};
	pid_t own_pid = 0;
	const char *config_path, *own_id_str;
	char log_file_path[128];
	char tmp_path[128];

	init_unprotected();

	monmod_page_size = sysconf(_SC_PAGE_SIZE);
	own_pid = getpid();
	
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

	/* Parse configuration. */
	NZ_TRY_EXCEPT(parse_config(config_path, &conf), exit(1));

	/* Open log file. */
	snprintf(log_file_path, sizeof(log_file_path), MONMOD_LOG_FILE,
	         own_id);
	if(0 > (monmod_log_fd = open(log_file_path, O_WRONLY | O_APPEND 
	                             | O_CREAT | O_TRUNC, 0664)))
	{
		WARNF("unable to open log file at %s: %s\n",
		      MONMOD_LOG_FILE,
		      strerror(errno));
		exit(1);
	}

	/* Initialize monitor; from this point forward, tracing is enabled. */
	SAFE_NZ_TRY(monitor_init(&monitor, own_id, &conf));

	/* The architecture-specific caller of this code issues a
	   monmod_reprotect call to initialize the module and protect the
	   module code after this and exits out of it. */
}
#pragma GCC pop_options

void 
__attribute__((destructor)) 
__attribute__((section("unprotected")))
monmod_library_destroy()
{
	unprotected_funcs.monitor_destroy(&monitor);
}

