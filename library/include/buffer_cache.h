#ifndef BUFFER_CACHE_H
#define BUFFER_CACHE_H

#include <stdbool.h>
#include "build_config.h"
#include "util.h"

typedef signed char cache_id;

/**
 * Take buffer and store it in the cache, returning an ID for later retrieval.
 * This will evict the least recently retrieved cache entry. The ID will be the
 * evicted entry's ID -- it is reused now to refer to the new buffer.
 */
cache_id cache_buffer(const char *buffer, size_t len);

int cache_buffer_with_id(cache_id id, const char *buffer, size_t len);

/**
 * Return -1 if the given buffer is not in the cache. Return the cache_id if
 * it is in the cache.
 */
cache_id cache_contains_buffer(const char *buffer, size_t len);

/**
 * Return pointer to a cached buffer, or NULL if no such buffer exists.
 */
char *retrieve_cached_buffer(cache_id id, size_t *len);

void log_cache();

#endif