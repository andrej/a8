#ifndef CONFIG_H
#define CONFIG_H

#include <sys/socket.h>

#define MAX_N_VARIANTS 8

/**
 * A variant is one instance of the monitored program. Multiple variants can
 * run on the same host, but they will need to run on separate ports
 * (encoded in the struct sockaddr) and they will ned separate IDs.
 */
struct variant_config {
	int id;
	struct sockaddr addr;
};

struct config {
	/**
	 * System calls that are not repeatable -- that is, system calls with
	 * outside-observable side-effects -- are only executed once on the 
	 * variant whose ID matches `leader_id`. The results of those system
	 * calls are then replicated to all other variants, so it appears as if
	 * they had executed the system call locally. Examples of non-repeatable
	 * system calls include `read()` on an open socket, or `time()`.
	 */
	int leader_id;
	size_t n_variants;
	struct variant_config variants[MAX_N_VARIANTS];
};

/**
 * Using libconfig, read and parse the configuration at `path` into the 
 * configuration structure `dest`.
 */
int parse_config(const char *path, struct config *dest);

/**
 * Return configuration variables for one specific variant.
 */
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