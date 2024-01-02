#include "buffer_cache.h"
#if USE_REPLICATION_CACHE

#include <assert.h>


/* ************************************************************************** *
 * Internals                                                                  *
 * ************************************************************************** */

#define HASH_OVERSIZE_FACTOR 4

static char cache[N_CACHE_ENTRIES][CACHE_ENTRY_MAX_SZ];
static size_t cache_lens[N_CACHE_ENTRIES] = {0};

// Map hash to cache_id for retrieval
static cache_id hash_to_id[HASH_OVERSIZE_FACTOR*N_CACHE_ENTRIES] = 
    {[0 ... sizeof hash_to_id / sizeof hash_to_id[0] - 1] = -1};
#define hash_to_id_len (sizeof(hash_to_id)/sizeof(hash_to_id[0]))
static int id_to_hash[N_CACHE_ENTRIES] = 
    {[0 ... (sizeof id_to_hash / sizeof id_to_hash[0]) - 1] = -1};

// History of the last N retrieved cache entries
struct access_history_item {
    bool occupied;
    cache_id id;
    struct access_history_item *next;
    struct access_history_item *prev;
};
struct access_history_item access_history[N_CACHE_ENTRIES] = {};
struct access_history_item *access_history_head = &access_history[0];
struct access_history_item *access_history_tail = &access_history[0];

static inline int hash_buffer(const char *buffer, size_t len)
{
    return sdbm_hash(len, buffer) % hash_to_id_len;
}

static inline void add_entry(cache_id id, int hash, const char *buffer, 
                             size_t len)
{
    hash_to_id[hash] = id;
    id_to_hash[id] = hash;
    cache_lens[id] = len;
    memcpy(cache[id], buffer, len);
}

static inline void remove_entry(cache_id id)
{
    //memset(cache[id], 0, cache_lens[id]);
    cache_lens[id] = 0;
    hash_to_id[id_to_hash[id]] = -1;
    id_to_hash[id] = -1;
    // It should be fine not to remove it from the access history.
}

static inline void mark_accessed(cache_id id)
{
    // If the list is empty, initialize it
    if(!access_history_head->occupied) {
        *access_history_head = (struct access_history_item) {
            true, id, NULL, NULL
        };
        return;
    }

    // If ID is present in access history, move it to the front.
    for(struct access_history_item *cur = access_history_head; 
        cur != NULL; cur = cur->next) {
        if(cur->id == id) {
            if(NULL == cur->prev) {
                // Already at the front, no need to move.
                assert(cur == access_history_head);
                return;
            } else if(access_history_tail == cur) {
                // This was the tail; after removing, new tail will be its prev.
                access_history_tail = cur->prev;
                assert(cur->next == NULL);
            }
            // Cut cur out of the chain...
            cur->prev->next = cur->next;
            if(cur->next != NULL) {
                cur->next->prev = cur->prev;
            }
            // ...and move it to the front.
            cur->next = access_history_head;  // old head
            cur->prev = NULL;
            access_history_head->prev = cur;
            access_history_head = cur;
            return;
        }
    }

    // If ID wasn't in the list, add it to the front now.
    struct access_history_item *new_head = NULL;
    // First, see if we can grow the list using empty memory.
    for(int i = 0; i < sizeof(access_history)/sizeof(access_history[0]); i++) {
        if(!access_history[i].occupied) {
            new_head = &access_history[i];
            break;
        }
    }
    // If not, replace the oldest item in the list and move it to the front
    if(NULL == new_head) {
        new_head = access_history_tail;
        if(access_history_tail->prev != NULL) {
            access_history_tail = access_history_tail->prev;
        } else {
            assert(access_history_tail == access_history_head);
        }
        access_history_tail->next = NULL;
    }
    assert(new_head != NULL);
    struct access_history_item *old_head = access_history_head;
    old_head->prev = new_head;
    assert(old_head != new_head);
    *new_head = (struct access_history_item) {
        true, id, old_head, NULL
    };
    access_history_head = new_head;
}

static inline int get_least_recently_accessed_id()
{
    if(access_history_tail->occupied) {
        return access_history_tail->id;
    }
    return -1;
}


/* ************************************************************************** *
 * API                                                                        *
 * ************************************************************************** */

cache_id cache_buffer(const char *buffer, size_t len)
{
    // Reject uncacheable buffers
    if(len > CACHE_ENTRY_MAX_SZ) {
        return -1;
    }

    // Get least recently used cache_id
    cache_id lru_id = 0;
    // While we still have free slots, use them.
    for(; id_to_hash[lru_id] != -1 && lru_id < N_CACHE_ENTRIES; lru_id++);
    // If no free slots remain, use least recently used.
    if(lru_id == N_CACHE_ENTRIES) {
        lru_id = get_least_recently_accessed_id();
    }

    cache_buffer_with_id(lru_id, buffer, len);

    return lru_id;
}

int cache_buffer_with_id(cache_id id, const char *buffer, size_t len)
{
    const int hash = hash_buffer(buffer, len);

    if(id_to_hash[id] != -1) {
        remove_entry(id);
    }
    if(hash_to_id[hash] != -1) {
#if VERBOSITY >= 4
        SAFE_LOGF("Hash collision! len_a = %lu, len_b = %lu\n",
                  len, cache_lens[hash_to_id[hash]]);
#endif
        remove_entry(hash_to_id[hash]);
    }
    add_entry(id, hash, buffer, len);
    mark_accessed(id);

    return 0;
}

cache_id cache_contains_buffer(const char *buffer, size_t len)
{
    const int hash = hash_buffer(buffer, len);
    const cache_id match = hash_to_id[hash];
    if(-1 == match) {
        return -1;
    }
    if(cache_lens[match] != len || 0 != memcmp(cache[match], buffer, len)) {
#if VERBOSITY >= 4
        SAFE_LOGF("Hash collision! len_a = %lu, len_b = %lu\n", len, cache_lens[match]);
#endif
        return -1;
    }
    return match;
}

char *retrieve_cached_buffer(cache_id id, size_t *len)
{
    if(id_to_hash[id] == -1) {
        return NULL;
    }

    *len = cache_lens[id];
    mark_accessed(id);
    return cache[id];
}

void log_cache()
{
    SAFE_LOG("CACHE LOG\n");
    SAFE_LOG("    hash_to_id = { ");
    for(int i = 0; i < sizeof(hash_to_id)/sizeof(hash_to_id[0]); i++) {
        SAFE_LOGF("[%3d] = %3hhd, ", i, hash_to_id[i]);
    }
    SAFE_LOG(" }\n");
    SAFE_LOG("    id_to_hash = { ");
    for(int i = 0; i < sizeof(id_to_hash)/sizeof(id_to_hash[0]); i++) {
        SAFE_LOGF("[%3d] = %3d, ", i, id_to_hash[i]);
    }
    SAFE_LOG(" }\n");
    SAFE_LOG("    cache_lens = { ");
    for(int i = 0; i < sizeof(cache_lens)/sizeof(cache_lens[0]); i++) {
        SAFE_LOGF("[%3d] = %3lu, ", i, cache_lens[i]);
    }
    SAFE_LOG(" } \n");
}

#endif