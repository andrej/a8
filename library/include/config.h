#ifndef CONFIG_H
#define CONFIG_H

#include <sys/socket.h>

#ifndef MAX_N_VARIANTS
#define MAX_N_VARIANTS 8
#endif
#ifndef MAX_N_BREAKPOINTS
#define MAX_N_BREAKPOINTS 4
#endif

/**
 * Variants are checkpointed each N-th time they hit breakpoints at the given
 * PC.
 */
struct breakpoint_config {
	void *pc;
	size_t instr_len;  /* width of instruction at pc; must be given in
	                      config until we include an instruction decoder */
	long interval;
};

/**
 * A variant is one instance of the monitored program. Multiple variants can
 * run on the same host, but they will need to run on separate ports
 * (encoded in the struct sockaddr) and they will ned separate IDs.
 */
struct variant_config {
	int id;
	struct sockaddr addr;
	size_t n_breakpoints;
	struct breakpoint_config breakpoints[MAX_N_BREAKPOINTS];
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
	/**
	 * The cross-checking policy can exempt some non-security critical 
	 * system calls from cross-checking.
	 */
	char policy[64];
	/**
	 * If set to a positive value, this will reset the variant to the last
	 * checkpoint after every # restore_interval system calls. Set too low,
	 * this will lead to an infinite loop. For server-type applications,
	 * this could potentially be useful as a moving target defense.
	 */
	int restore_interval;
	/**
	 * If set to > 1, replication buffers are exchanged in batches of up to
	 * the given size between variants. System call replication information
	 * is always exchanged when
	 *  (a) a cross-checked system call occurs (all variants need to be able
	 *      to advance to the system call)
	 *  (b) the batch size is reached
	 */
	int replication_batch_size;
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