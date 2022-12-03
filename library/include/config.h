#ifndef CONFIG_H
#define CONFIG_H

#include <sys/socket.h>

#define MAX_N_VARIANTS 8

struct variant_config {
	int id;
	struct sockaddr addr;
};

struct config {
	int leader_id;
	size_t n_variants;
	struct variant_config variants[MAX_N_VARIANTS];
};


int parse_config(const char *path, struct config *dest);

#endif