#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <stdbool.h>
#include <unistd.h>
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

struct environment {
	struct communicator *comm;
	int leader_id;
	bool is_leader;
	size_t n_descriptors;
	struct descriptor_info descriptors[128];
};

/**
 * Initialize the environment with default file descriptors.
 */
void env_init(struct environment *env, 
              struct communicator *comm,
              struct config *config, 
              int own_id);

static inline int env_add_descriptor(struct environment *env, 
                                     int local_fd, int canonical_fd, int flags)
{
	if(env->n_descriptors >= 
		sizeof(env->descriptors)/sizeof(env->descriptors[0])) {
		return 1;
	}
	size_t i = env->n_descriptors;
	env->descriptors[i].flags = flags;
	env->descriptors[i].canonical_fd = canonical_fd;
	env->descriptors[i].local_fd = local_fd;
	env->n_descriptors++;
	return 0;
}

/**
 * Add descriptor to the table with the given flags and local file descriptor.
 * The added canonical fd is returned.
 */
static inline int env_add_local_descriptor(struct environment *env, 
                                           int fd, int flags)
{
	size_t i = env->n_descriptors;
	env_add_descriptor(env, fd, i, flags);
	return i;
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


#endif