#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "config.h"
#include "communication.h"
#include "util.h"

#define MAX_N_DESCRIPTOR_MAPPINGS 256
#define DI_FREE              0x0  // DI stands for Descriptor Information
#define DI_PRESENT           0x1
#define DI_OPENED_LOCALLY    0x2 
#define DI_OPENED_ON_LEADER  0x4
#define DI_UNCHECKED         0x8  /* Any operations involving this descriptor
                                     should not be cross-checked. */

#define is_open_locally(env, di) \
	((di->flags & DI_OPENED_LOCALLY) \
	 || (env->is_leader && (di->flags & DI_OPENED_ON_LEADER)))

enum descriptor_type {
	FILE_DESCRIPTOR,
	SOCKET_DESCRIPTOR,
	EPOLL_DESCRIPTOR
};

struct descriptor_info {
	int flags;
	int local_fd;
	enum descriptor_type type;
};

struct epoll_data_info {
	int epfd;
	int fd;
	struct epoll_event data;
	struct epoll_data_info *prev;
	struct epoll_data_info *next;
};

struct epoll_data_infos {
	struct epoll_data_info *head;
	struct epoll_data_info *tail;
};

#define for_each_epoll_data_info(epoll_data_infos, x) \
	for((x) = (epoll_data_infos).head; (x) != NULL; (x) = (x)->next)

/**
 * The environment structure is used to encode information about the execution
 * of the program so far. Its primary purpose currently is to capture opened 
 * file descriptors and maintain a mapping between a 'canonical' file descriptor
 * -- the one that the executing program sees and that is compared across
 * variants -- and the 'local' file descriptor -- the one that the kernel sees
 * and corresponds to an actual open file on the local machine. We need to 
 * maintain two sets, since not all file descriptors are open on all hosts, but
 * for cross-checking to work, the descriptors need to be the same everywhere.
 */
struct environment {
	struct communicator *comm;
	int leader_id;
	bool is_leader;
	size_t n_descriptors;
	/* Descriptors are mapped in an array where the index into the array
	   is the canonical file descriptor number, pointing to flags and 
	   the corresponding locally-opened file descriptor. */
	struct descriptor_info descriptors[MAX_N_DESCRIPTOR_MAPPINGS];
	struct epoll_data_infos epoll_data_infos;
};

/**
 * Initialize the environment with default file descriptors stdin, stdout,
 * stderr.
 */
void env_init(struct environment *env, 
              struct communicator *comm,
              struct config *config, 
              int own_id);

static inline struct descriptor_info *
env_add_descriptor(struct environment *env, 
		   int local_fd, int canonical_fd, int flags,
		   enum descriptor_type type)
{
	const int i = canonical_fd;
	if(DI_FREE != env->descriptors[i].flags) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "A descriptor with canonical ID %d already "
		          "exists.\n", i);
#endif
		return NULL;
	}
	env->descriptors[i].flags = DI_PRESENT | flags;
	env->descriptors[i].local_fd = local_fd;
	env->descriptors[i].type = type;
	env->n_descriptors++;
#if VERBOSITY >= 3
	SAFE_LOGF(log_fd, "Added descriptor mapping %d -> %d.\n", canonical_fd, 
	          local_fd);
#endif
	return &env->descriptors[i];
}

/**
 * Add descriptor to the table with the given flags and local file descriptor.
 * The added canonical fd is returned.
 */
static inline struct descriptor_info *
env_add_local_descriptor(struct environment *env, 
			 int fd, int flags,
			 enum descriptor_type type)
{
	/* Find the next free canonical ID. 
	   Programs may assume that IDs 0, 1, 2 are stdin, stdout and stderr,
	   respectively, so we skip those for safety (even though our 
	   initialization adding these three default descriptors should already
	   take care of this). */
	size_t canonical = 3;
	for(; canonical < MAX_N_DESCRIPTOR_MAPPINGS; canonical++) {
		if(DI_FREE == env->descriptors[canonical].flags) {
			break;
		}
	}
	if(DI_FREE != env->descriptors[canonical].flags) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "No more space for descriptor mappings.%s",
		          "\n");
#endif
		return NULL;
	}
	return env_add_descriptor(env, fd, canonical, flags, type);
}

static inline int canonical_fd_for(struct environment *env,
                                   struct descriptor_info *di)
{
	size_t i = (di - env->descriptors);
	if(i > MAX_N_DESCRIPTOR_MAPPINGS || !(DI_PRESENT & di->flags)) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "No descriptor mapping with local fd %d "
		          "registered (%p).\n", di->local_fd, di);
#endif
		return -1;
	}
	return i;
}

static inline int 
env_del_descriptor(struct environment *env, struct descriptor_info *di)
{
	const int i = canonical_fd_for(env, di);
	if(0 > i) {
		return 1;
	}
#if VERBOSITY >= 3
	SAFE_LOGF(log_fd, "Removing descriptor mapping %d -> %d.\n", 
	          i, env->descriptors[i].local_fd);
#endif
	env->descriptors[i].flags = DI_FREE;
	env->n_descriptors--;
	return 0;
}

static inline struct descriptor_info 
*env_get_local_descriptor_info(struct environment *env, int fd)
{
	for(int i = 0; i < MAX_N_DESCRIPTOR_MAPPINGS; i++) {
		if(DI_FREE == env->descriptors[i].flags) {
			continue;
		}
		if(fd == env->descriptors[i].local_fd) {
			return &env->descriptors[i];
		}
	}
	return NULL;
}

static inline struct descriptor_info 
*env_get_canonical_descriptor_info(struct environment *env, int fd)
{
	if(0 > fd || fd >= MAX_N_DESCRIPTOR_MAPPINGS
	   || !(env->descriptors[fd].flags & DI_PRESENT)) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "No such canonical descriptor: %d.\n", fd);
#endif
		return NULL;
	}
	return &env->descriptors[fd];
}

/**
 * Find an epoll_data_info or return NULL
 */
struct epoll_data_info *get_epoll_data_info_for(struct environment *env,
                                                int epfd,
						int fd,
						uint32_t events);

/**
 * Copy and append a new epoll_data_info structure 
 */
int append_epoll_data_info(struct environment *env, 
                           struct epoll_data_info info);
/**
 * Remove a epoll_data_info from the environment
 */
int remove_epoll_data_info(struct environment *env, 
                           struct epoll_data_info *info);

/**
 * Sanitize the file descriptor state in a child process after a call to fork()
 * issued by the checkpointing mechanism. This is required to clean up 
 * situations where the semantics of fork() don't exactly mirror a duplication
 * of file descriptors etc. 
 */
int checkpointed_environment_fix_up(struct environment *env);

#endif