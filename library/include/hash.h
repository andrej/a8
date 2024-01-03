#ifndef HASH_H
#define HASH_H

#include <stdlib.h>
#include <stdint.h>
#include "xxhash.h"
#include "build_config.h"

static inline unsigned long sdbm_hash(const unsigned char *buf, size_t len)
{
	unsigned long hash = 0;
	unsigned int c = 0;
	for(size_t i = 0; i < len; i++) {
		c = buf[i];
		hash = c + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

static inline unsigned long hash(const unsigned char *buf, size_t len)
{
#if USE_XXH
	const uint64_t seed = 0;
#endif
#if USE_XXH
	return XXH32(buf, len, seed);
#else
	return sdbm_hash(buf, len);
#endif
}

#endif