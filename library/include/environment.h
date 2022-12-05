#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <unistd.h>
#include "communication.h"

#define DI_OPENED_LOCALLY (1)
#define DI_OPENED_ON_LEADER (1 << 1)
#define DI_IS_SOCKET (1 << 2)

struct descriptor_info {
	int flags;
	int canonical_fd;
	int local_fd;
};

struct environment {
	struct communicator *comm;
	size_t n_descriptors;
	struct descriptor_info descriptors[128];
};

static inline int add_descriptor(struct environment *env, int fd, int flags)
{
	size_t i = env->n_descriptors;
	env->descriptors[i].flags = flags;
	env->descriptors[i].canonical_fd = i;
	env->descriptors[i].local_fd = fd;
	env->n_descriptors++;
	return env->n_descriptors;
}

#endif