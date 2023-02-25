#ifndef POLICY_H
#define POLICY_H

#include <stddef.h>
#include <stdbool.h> 

struct policy {
	const char *name;
	bool (*is_exempt)(long);
};

extern struct policy policies[];

#define POLICIES(X) \
	X(full) \
	X(leak) \
	X(code)

#define POLICY_DEF(name) \
	bool policy_ ## name ## _is_exempt(long syscall_no);
POLICIES(POLICY_DEF)

struct policy *policy_from_str(const char *str);
static inline bool policy_is_exempt(struct policy *policy, long syscall_no)
{
	if(NULL == policy) {
		return false;
	}
	return policy->is_exempt(syscall_no);
}

#endif