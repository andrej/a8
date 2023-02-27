#define _GNU_SOURCE

#include "build_config.h"
#if ENABLE_CHECKPOINTING == CRIU_CHECKPOINTING

#include <dlfcn.h>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <criu/criu.h>
#include <stdbool.h>
#include <string.h>
#include <libgen.h> // dirname
#include <sys/fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "util.h"
#include "dumper_restorer.h"


// Configuration ... hard-coded for now
#define CRIU_SERVICE_ADDRESS "/var/run/criu-service.socket"
#define CRIU_IMAGES_DIRECTORY "./criu_images"

// Declarations
void handle_signal(int sig, siginfo_t *si, void *_context);
static int initialize_criu();
static int dump(const char *images_directory, pid_t pid, int dump_index);
static int restore(const char *images_directory, pid_t pid, int dump_index);
void get_own_path(char *dest, size_t size);
enum criu_request {
	NONE,
	DUMP,
	RESTORE,
	EXIT
};

// Globals
static criu_opts *our_criu_opts = NULL;
static volatile enum criu_request request = NONE; // updated by signal handler
static struct checkpoint_env *cenv = NULL;
pid_t child = 0;
char criu_path[256];

void dumper_restorer_main(struct checkpoint_env *cenv, pid_t child)
{
	char own_path[256] = {'\0'};
	get_own_path(own_path, sizeof(own_path));
	cenv = cenv;
	child = child;
	if(NULL != own_path) {
		snprintf(criu_path, sizeof(criu_path), 
		         "%s/../../dependencies/criu_install", 
		         dirname(own_path));
	} else {
		strcpy(criu_path, "../../dependencies/criu_install");
	}

	/* Set up image directory */
	NZ_TRY_EXCEPT(mkdir(CRIU_IMAGES_DIRECTORY, 0775),
	              exit(1));

	/* Set up signal handlers. */
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handle_signal;
	NZ_TRY_EXCEPT(sigaction(SIGUSR1, &sa, NULL),
	              exit(1));
	NZ_TRY_EXCEPT(sigaction(SIGUSR2, &sa, NULL),
	              exit(1));
	NZ_TRY_EXCEPT(sigaction(SIGINT, &sa, NULL) ,
	              exit(1));
	NZ_TRY_EXCEPT(sigaction(SIGTERM, &sa, NULL),
	              exit(1));

	/* Let child now that we are ready to receive requests. */
	NZ_TRY_EXCEPT(kill(child, SIGUSR1),
	              exit(1));

	/* Now, run as long as child runs; actual work is done when we receive
	   a signal. */
	int n_dumps = 0;
	while(waitpid(child, NULL, WNOHANG) == 0 && request != EXIT) {
		switch(request) {
			case DUMP:
				NZ_TRY_EXCEPT(initialize_criu(),
				              exit(1));
				NZ_TRY_EXCEPT(dump(CRIU_IMAGES_DIRECTORY, 
				                   child, n_dumps),
					      exit(1));
				n_dumps++;
				break;
			case RESTORE:
				NZ_TRY_EXCEPT(initialize_criu(),
				              exit(0));
				NZ_TRY_EXCEPT(restore(CRIU_IMAGES_DIRECTORY, 
				                      child, n_dumps-1),
					      exit(1));
				break;
			default:
			case NONE:
			case EXIT:
				break;
			
		}
		request = NONE;
	}
	exit(0);
}

void handle_signal(int sig, siginfo_t *si, void *_context)
{
	switch(sig) {
		case SIGUSR1:
			request = DUMP;
			break;
		case SIGUSR2:
			request = RESTORE;
			break;
		case SIGINT:
		case SIGTERM:
			request = EXIT;
			break;
	}
}

static int initialize_criu() {
	NZ_TRY(criu_local_init_opts(&our_criu_opts));
	criu_local_set_service_address(our_criu_opts, CRIU_SERVICE_ADDRESS);
	return 0;
}

static int dump(const char *images_directory, pid_t pid, int dump_index) {
	char prev_image_directory[256];
	char this_image_directory[256];
	snprintf(prev_image_directory, sizeof(prev_image_directory), "../%d", 
	         dump_index - 1);
	snprintf(this_image_directory, sizeof(this_image_directory),
	         "%s/%d", images_directory, dump_index);
	if(mkdir(this_image_directory, 0775) != 0) {
		if(errno != EEXIST) {
			return 1;
		}
	}
	int fd = -1;
	LZ_TRY(fd = open(this_image_directory, O_DIRECTORY));
	criu_local_set_images_dir_fd(our_criu_opts, fd);
#if USE_INCREMENTAL_DUMPS
	if(dump_index > 0) {
		criu_local_set_parent_images(our_criu_opts, prev_image_directory);
	}
	// criu_local_set_track_mem(our_criu_opts, true);
#endif
	criu_local_set_pid(our_criu_opts, pid);
	NZ_TRY(criu_local_set_log_file(our_criu_opts, "criu_dump.log"));
	criu_local_set_log_level(our_criu_opts, 4);
	criu_local_set_shell_job(our_criu_opts, true);
	criu_local_set_leave_running(our_criu_opts, true);
	criu_local_set_tcp_established(our_criu_opts, true);
	criu_local_set_tcp_skip_in_flight(our_criu_opts, true);
	NZ_TRY(criu_local_dump(our_criu_opts));
	/* Notify child process of completion of dump. We will also need to do
	   this upon restore, since we dumped the child in a "waiting for dump
	   to complete" state */
	kill(child, SIGUSR1);
	close(fd);
	return 0;
}

static int restore(const char *images_directory, pid_t pid, int dump_index) {
	char prev_image_directory[256];
	char this_image_directory[256];
	char path[256];
	snprintf(prev_image_directory, sizeof(prev_image_directory), "../%d", 
	         dump_index - 1);
	snprintf(this_image_directory, sizeof(this_image_directory),
	         "%s/%d", images_directory, dump_index);
	snprintf(path, sizeof(path), "PATH=%s/", criu_path);
	LZ_TRY(dump_index);
	/* Reap any children we might still have. */ 
	kill(child, SIGKILL);
	while(wait(NULL) > 0);
	int fd = -1;
	NZ_TRY(fd = open(this_image_directory, O_DIRECTORY));
	criu_local_set_images_dir_fd(our_criu_opts, fd);
#if USE_INCREMENTAL_DUMPS
	if(dump_index > 1) {
		criu_local_set_parent_images(our_criu_opts, prev_image_directory);
	}
	// criu_local_set_track_mem(our_criu_opts, true);
#endif
	criu_local_set_pid(our_criu_opts, pid);
	criu_local_set_log_level(our_criu_opts, 4);
	criu_local_set_shell_job(our_criu_opts, true);
	criu_local_set_leave_running(our_criu_opts, true);
	criu_local_set_tcp_established(our_criu_opts, true);
	NZ_TRY(criu_local_set_log_file(our_criu_opts, "criu_restore.log"));
	putenv((char *)path);
	NZ_TRY(criu_local_restore_child(our_criu_opts));
	/* The restored image will be in the waiting loop that the process 
	   enters after sending a dump request. This indicates completion of
	   the "dump", and allows the frozen process to continue out of
	   create_criu_checkpoint(). */
	//kill(child, SIGUSR1);
	close(fd);
	return 0;
}

void get_own_path(char *dest, size_t size)
{
	Dl_info info;
	if(dladdr(get_own_path, &info) == 0) {
		return;
	}
	strncpy(dest, info.dli_fname, size);
}

#endif