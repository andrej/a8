#ifndef HANDLERS_SUPPORT_H
#define HANDLERS_SUPPORT_H

#include <linux/limits.h>

#include "handlers.h"
#include "build_config.h"
#include "environment.h"
#include "util.h"


#define get_di(arg_i) ({ \
	struct descriptor_info *di = env_get_canonical_descriptor_info( \
		env, canonical->args[arg_i]); \
	if(NULL == di) { \
		return DISPATCH_ERROR; \
	} \
	di; \
})

#define remap_fd(di, arg_i) { \
	actual->args[arg_i] = (di)->local_fd; \
}

#define get_pid_info(arg_i) ({ \
	struct pid_info *pi = env_get_pid_info(env, canonical->args[arg_i]); \
	if(NULL == pi) { \
		return DISPATCH_ERROR; \
	} \
	pi; \
})

#define remap_pid(pi, arg_i) { \
	actual->args[arg_i] = (pi)->local_pid; \
}

#define alloc_scratch(sz) { \
	if(sz < handler_scratch_buffer + sizeof(handler_scratch_buffer)  \
	            - (char *)next_preallocated) { \
		*scratch = next_preallocated; \
		*(size_t *)(next_preallocated + sz) = sz; \
		next_preallocated += sz + sizeof(size_t); \
	} else { \
		SAFE_Z_TRY(*scratch = safe_malloc(sz + sizeof(size_t))); \
		*(size_t *)*scratch = sz + sizeof(size_t); \
		*scratch = (*scratch) + sizeof(size_t); \
		if(NULL == scratch) { \
			return DISPATCH_ERROR; \
		} \
	} \
}

#define prev_preallocated() ({ \
	void *res =  handler_scratch_buffer; \
	if(next_preallocated != handler_scratch_buffer) { \
		size_t prev_sz = *(size_t *)(next_preallocated \
		                             - sizeof(size_t)); \
		res = next_preallocated - prev_sz - sizeof(size_t); \
	} \
	res; \
})

#define free_scratch() { \
	void *prev_pa = prev_preallocated(); \
	if(NULL != scratch && NULL != *scratch \
	   && prev_pa != *scratch) { \
	   	*scratch = (*scratch) - sizeof(size_t); \
	   	size_t sz = *(size_t *)(*scratch); \
		safe_free(*scratch, sz); \
	} else if(prev_pa == *scratch) { \
		next_preallocated = prev_pa; \
	} \
}

#define dispatch_leader_if_needed(di, addl_flags) ({ \
	int flags = addl_flags; \
	if(NULL != (di) && (di)->flags & DI_OPENED_ON_LEADER) { \
		flags |= DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION; \
	} else { \
		flags |= DISPATCH_EVERYONE; \
	} \
	flags; \
})

#define post_call_error() { \
	return 1; \
}

#define write_back_canonical_return() \
	if(canonical->ret_flags & ARG_FLAG_REPLICATE) { \
		actual->ret = canonical->ret; \
	}

#define redirect_enter(other) \
	SYSCALL_ENTER(other)(env, handler, actual, canonical, scratch);

#define redirect_post_call(other) \
	SYSCALL_POST_CALL(other)(env, handler, dispatch, actual, canonical, \
	                         scratch);

#define redirect_exit(other) \
	SYSCALL_EXIT(other)(env, handler, dispatch, actual, canonical, scratch)

static inline int get_dispatch_by_path(const char *path)
{
	static struct cache {
		char key[PATH_MAX];
		char value[PATH_MAX];
	} full_path_cache[32] = {};
	int cache_i = 0;
	int cache_len = 0;
	const char *full_path = NULL;
	char realpath_buf[PATH_MAX];

	// Check for path in cache
	for(int i = 0; i < cache_len; i++) {
		if(strlen(path) == strlen(full_path_cache[i].key)
		   && 0 == strncmp(path, full_path_cache[i].key, PATH_MAX)) {
			full_path = full_path_cache[i].value;
		}
	}

	// Add to cache if not found
	if(NULL == full_path) {
		full_path = realpath(path, realpath_buf);
		if(NULL != full_path) {
			strncpy(full_path_cache[cache_i].key, path, PATH_MAX);
			strncpy(full_path_cache[cache_i].value, full_path, 
			        PATH_MAX);
			cache_i = (cache_i + 1) %
			          sizeof(full_path_cache)
				  /sizeof(full_path_cache[0]);
			if(cache_i > cache_len) {
				cache_len = cache_i;
			}
		}
	}

	// Actually handle full_path 
	if(NULL == full_path) {
		/* If realpath() errored, it is likely because the path does not
		   exist. Just dispatch it for everyone and let them handle the
		   error. */
		return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	const char dev_prefix[] = "/dev/";
	const char proc_prefix[] = "/proc/";
	const char etc_localtime[] = "/etc/localtime";
	const char etc_group[] = "/etc/group";
	const char zoneinfo[] = "/usr/share/zoneinfo/";
	if(strncmp(full_path, dev_prefix, sizeof(dev_prefix)-1) == 0) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		| DISPATCH_NEEDS_REPLICATION;
	} else if(strncmp(full_path, proc_prefix, sizeof(proc_prefix)-1) == 0
	          || strncmp(full_path, etc_localtime, sizeof(etc_localtime)-1
    		      == 0)
		  || strncmp(full_path, etc_group, sizeof(etc_group)-1) == 0
		  || strncmp(full_path, zoneinfo, sizeof(zoneinfo)-1) == 0
		  || NULL != strstr(full_path, "libnss") // FIXME
		  || NULL != strstr(full_path, "libnsl")
		  ) {
		return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

#endif