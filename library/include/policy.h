#ifndef POLICY_H
#define POLICY_H

#include <stddef.h>
#include <stdbool.h> 
#include "syscall_info.h"
#include "environment.h"

struct policy {
	const char *name;
	bool (* const is_exempt)(const struct syscall_info * const, 
	                         const struct environment * const);
};

extern struct policy policies[];

#define POLICY_IS_EXEMPT_FN(name) policy_ ## name ## _is_exempt
#define policy_is_exempt_static(name, ...) \
	POLICY_IS_EXEMPT_FN(name)(__VA_ARGS__)

#define POLICIES(X) \
	X(full) \
	X(base) \
	X(nonsocket_ro) \
	X(nonsocket_rw) \
	X(socket_ro) \
	X(socket_rw) \
	X(socket_rw_oc)

#define POLICY_DEF(name) \
	bool POLICY_IS_EXEMPT_FN(name)( \
		const struct syscall_info * const canonical, \
		const struct environment * const env);
POLICIES(POLICY_DEF)
#undef POLICY_DEF

struct policy *policy_from_str(const char *str);
static inline bool policy_is_exempt(struct policy * const policy, 
                                    struct syscall_info * const canonical,
                                    const struct environment * const env)
{
	if(NULL == policy) {
		return false;
	}
	return policy->is_exempt(canonical, env);
}

#endif