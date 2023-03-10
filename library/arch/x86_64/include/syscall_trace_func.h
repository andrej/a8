#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <asm/ptrace.h>  // pt_regs

struct syscall_trace_func_stack {
	struct pt_regs regs;
};

void monmod_syscall_trace_enter();

#endif