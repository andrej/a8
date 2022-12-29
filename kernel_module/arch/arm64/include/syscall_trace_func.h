#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <linux/ptrace.h>

struct syscall_trace_func_stack
{
// low addr, top of stack
	struct pt_regs regs;
// high addr, bottom of stack
};

#endif