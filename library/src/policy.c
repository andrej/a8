#include "policy.h"
#include "handler_table.h"

#define POLICY_ARR_DEF(X) {#X, policy_ ## X ## _is_exempt},
struct policy policies[] = {
	POLICIES(POLICY_ARR_DEF)
};

#define POLICY_EXEMPT(X) bool policy_ ## X ## _is_exempt(long syscall_no)

POLICY_EXEMPT(full) {
	return false;
}

POLICY_EXEMPT(leak) {
	switch(syscall_no) {
		case SYSCALL_write_CANONICAL:
		case SYSCALL_writev_CANONICAL:
		case SYSCALL_ioctl_CANONICAL:
		case SYSCALL_sendfile_CANONICAL:
		case SYSCALL_mmap_CANONICAL:
		case SYSCALL_mprotect_CANONICAL:
			return false;
		default:
			return true;
	}
}

POLICY_EXEMPT(code) {
	switch(syscall_no) {
		case SYSCALL_mmap_CANONICAL:
		case SYSCALL_mprotect_CANONICAL:
			return false;
		default:
			return true;
	}
}

struct policy *policy_from_str(const char *str)
{
	for(struct policy *policy = &policies[0];
	    policy < policies + (sizeof(policies)/sizeof(policies[0]));
	    policy++) {
		if(0 == strcmp(policy->name, str)) {
			return policy;
		}
	}
	return NULL;
}
