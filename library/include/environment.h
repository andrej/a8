#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "config.h"
#include "communication.h"

#define DI_OPENED_LOCALLY    0x1 
#define DI_OPENED_ON_LEADER  0x2
#define DI_IS_SOCKET         0x4

struct descriptor_info {
	int flags;
	int canonical_fd;
	int local_fd;
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

struct environment {
	struct communicator *comm;
	int leader_id;
	bool is_leader;
	size_t n_descriptors;
	struct descriptor_info descriptors[128];
	struct epoll_data_infos epoll_data_infos;
};

/**
 * Initialize the environment with default file descriptors.
 */
void env_init(struct environment *env, 
              struct communicator *comm,
              struct config *config, 
              int own_id);

static inline struct descriptor_info *
env_add_descriptor(struct environment *env, 
		   int local_fd, int canonical_fd, int flags)
{
	if(env->n_descriptors >= 
		sizeof(env->descriptors)/sizeof(env->descriptors[0])) {
		return NULL;
	}
	size_t i = env->n_descriptors;
	env->descriptors[i].flags = flags;
	env->descriptors[i].canonical_fd = canonical_fd;
	env->descriptors[i].local_fd = local_fd;
	env->n_descriptors++;
	return &env->descriptors[i];
}

/**
 * Add descriptor to the table with the given flags and local file descriptor.
 * The added canonical fd is returned.
 */
static inline struct descriptor_info *
env_add_local_descriptor(struct environment *env, 
			 int fd, int flags)
{
	size_t i = env->n_descriptors + 15;
	return env_add_descriptor(env, fd, i, flags);
}

static inline int 
env_del_descriptor(struct environment *env, struct descriptor_info *di)
{
	size_t i = (di - env->descriptors);
	memmove(&env->descriptors[i], &env->descriptors[i+1],
	        (&env->descriptors[env->n_descriptors] - &env->descriptors[i])
		* sizeof(env->descriptors[0]));
	env->n_descriptors--;
	return 0;
}

static inline struct descriptor_info 
*env_get_local_descriptor_info(struct environment *env, int fd)
{
	for(size_t i = 0; i < env->n_descriptors; i++) {
		if(env->descriptors[i].local_fd == fd) {
			return &env->descriptors[i];
		}
	}
	return NULL;
}

static inline struct descriptor_info 
*env_get_canonical_descriptor_info(struct environment *env, int fd)
{
	for(size_t i = 0; i < env->n_descriptors; i++) {
		if(env->descriptors[i].canonical_fd == fd) {
			return &env->descriptors[i];
		}
	}
	return NULL;
}

static inline int canonical_to_local_fd(struct environment *env, int fd)
{
	struct descriptor_info *di;
	di = env_get_canonical_descriptor_info(env, fd);
	if(NULL == di) {
		return -1;
	}
	return di->local_fd;
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

#endif