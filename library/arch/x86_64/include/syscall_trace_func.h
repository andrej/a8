#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <sys/user.h>

struct syscall_trace_func_args {
	struct user_regs_struct regs;
	unsigned long syscall_no;
	void *ret_addr;
};

void monmod_syscall_trace_enter();

#endif