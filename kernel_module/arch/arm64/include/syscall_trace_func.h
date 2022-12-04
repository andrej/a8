#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <linux/ptrace.h>

struct syscall_trace_func_stack
{
// low addr, top of stack
    long unused; /* for alignment purposes */
	long ret_addr;
	struct pt_regs saved_regs;
// high addr, bottom of stack
};

#endif