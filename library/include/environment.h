#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "communication.h"
#include "util.h"
#include "list.h"

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

struct descriptor_info_list list_struct_def(struct descriptor_info, 
                                            MAX_N_DESCRIPTOR_MAPPINGS);


#define MAX_N_PID_MAPPINGS 256
#define CANONICAL_PID_BASE 1000
struct pid_info {
	pid_t local_pid;
};

struct pid_info_list list_struct_def(struct pid_info, MAX_N_PID_MAPPINGS);

struct epoll_data_info {
	int epfd;
	int fd;
	struct epoll_event event;
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
	size_t n_descriptors;
	/* Descriptors are mapped in an array where the index into the array
	   is the canonical file descriptor number, pointing to flags and 
	   the corresponding locally-opened file descriptor. */
	struct descriptor_info_list descriptors;
	struct pid_info_list children_pids;
	pid_t pid;
	pid_t ppid;
	struct epoll_data_infos epoll_data_infos;
	bool is_leader;
};

/**
 * Initialize the environment with default file descriptors stdin, stdout,
 * stderr.
 */
void env_init(struct environment *env, bool is_leader);

static inline struct descriptor_info *
env_add_descriptor(struct environment *env, 
		   int local_fd, int canonical_fd, int flags,
		   enum descriptor_type type)
{
	const int i = canonical_fd;
	struct descriptor_info di = {};
	if(NULL != list_get_i(env->descriptors, i)) {
#if VERBOSITY >= 3
		SAFE_WARNF("A descriptor with canonical ID %d already "
		           "exists.\n", i);
#endif
		return NULL;
	}
	di.flags = DI_PRESENT | flags;
	di.local_fd = local_fd;
	di.type = type;
	list_put_at(env->descriptors, di, i);
	env->n_descriptors++;
#if VERBOSITY >= 3
	SAFE_LOGF("Added descriptor mapping %d -> %d.\n", canonical_fd, 
	          local_fd);
#endif
	return list_get_i(env->descriptors, i);
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
	canonical = list_get_next_free_i(env->descriptors);
	if(canonical < 0 || list_capacity(env->descriptors) <= canonical)  {
		SAFE_WARN("No more space for descriptor mappings.");
		return NULL;
	}
	return env_add_descriptor(env, fd, canonical, flags, type);
}

static inline int env_canonical_fd_for(struct environment *env,
                                       struct descriptor_info *di)
{
	size_t i = (di - env->descriptors.items);
	if(i > MAX_N_DESCRIPTOR_MAPPINGS || !(DI_PRESENT & di->flags)) {
		SAFE_WARNF("No descriptor mapping with local fd %d registered "
		          "(%p).\n", di->local_fd, di);
		return -1;
	}
	return i;
}

static inline int 
env_del_descriptor(struct environment *env, struct descriptor_info *di)
{
	struct descriptor_info *in_list = NULL;
	const int i = env_canonical_fd_for(env, di);
	in_list = list_get_i(env->descriptors, i);
	if(0 > i || NULL == in_list) {
		return 1;
	}
#if VERBOSITY >= 4
	SAFE_LOGF("Removing descriptor mapping %d -> %d.\n", 
	          i, in_list->local_fd);
#endif
	list_del_i(env->descriptors, i);
	env->n_descriptors--;
	return 0;
}

static inline struct descriptor_info 
*env_get_local_descriptor_info(struct environment *env, int fd)
{
	size_t i = 0;
	list_for_each(env->descriptors, i) {
		if(!list_item_is_occupied(env->descriptors, i)) {
			continue;
		}
		if(fd == env->descriptors.items[i].local_fd) {
			return &env->descriptors.items[i];
		}
	}
	return NULL;
}

static inline struct descriptor_info 
*env_get_canonical_descriptor_info(struct environment *env, int fd)
{
	struct descriptor_info *ret = NULL;
	ret = list_get_i(env->descriptors, fd);
	if(NULL == ret) {
		SAFE_WARNF("No such canonical descriptor: %d.\n", fd);
		return NULL;
	}
	return ret;
}

static inline struct pid_info
*env_add_local_pid_info(struct environment *env, pid_t local_pid)
{
	int i = list_get_next_free_i(env->children_pids);
	pid_t canonical_pid = i + CANONICAL_PID_BASE;
	struct pid_info pid_info = {};
	pid_info.local_pid = local_pid;
	list_put_at(env->children_pids, pid_info, i);
#if VERBOSITY >= 4
	SAFE_LOGF("Added PID mapping %d -> %d.\n", canonical_pid, local_pid);
#endif
	return list_get_i(env->children_pids, i);
}

static inline struct pid_info
*env_get_pid_info(struct environment *env, pid_t canonical_pid)
{
	struct pid_info *ret = NULL;
	ret = list_get_i(env->children_pids, canonical_pid 
	                                     - CANONICAL_PID_BASE);
	if(NULL == ret) {
		SAFE_WARNF("No such canonical child PID: %d.\n", canonical_pid);
	}
	return ret;
}

static inline struct pid_info
*env_get_local_pid_info(struct environment *env, pid_t local_pid)
{
	struct pid_info *ret = NULL;
	size_t i = 0;
	list_for_each(env->children_pids, i) {
		if(!list_item_is_occupied(env->children_pids, i)) {
			continue;
		}
		if(local_pid == env->children_pids.items[i].local_pid) {
			return &env->children_pids.items[i];
		}
	}
	return ret;
}

static inline int env_canonical_pid_for(struct environment *env,
                                        struct pid_info *pi)
{
	size_t i = (pi - env->children_pids.items);
	if(i > MAX_N_PID_MAPPINGS) {
		SAFE_WARNF("No PID mapping with local PID %d registered "
		          "(%p).\n", pi->local_pid, pi);
		return -1;
	}
	return i + CANONICAL_PID_BASE;
}

static inline int
env_del_pid_info(struct environment *env, struct pid_info *pid_info)
{
	int i = env_canonical_pid_for(env, pid_info) - CANONICAL_PID_BASE;
	if(0 > i) {
		return 1;
	}
	if(0 != list_del_i(env->children_pids, i)) {
		SAFE_WARNF("Cannot remove PID info %d.\n", i);
		return 1;
	}
	return 0;
}

/**
 * Find an epoll_data_info or return NULL
 */
struct epoll_data_info *get_epoll_data_info_for(struct environment *env,
                                                int epfd,
						int fd,
						uint32_t events);

struct epoll_data_info *purge_epoll_data_fd(struct environment *env, int fd);

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