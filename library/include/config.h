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

static inline struct variant_config *get_variant(struct config *conf, int id)
{
	for(int i = 0; i < conf->n_variants; i++) {
		if(conf->variants[i].id == id) {
			return &conf->variants[i];
		}
	}
	return NULL;
}

#endif