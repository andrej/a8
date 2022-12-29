#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <stdint.h>

struct pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
	uint64_t orig_addr_limit;
	uint64_t unused;	// maintain 16 byte alignment
};

struct syscall_trace_func_stack {
	struct pt_regs regs;
};

void monmod_syscall_trace_enter();

#endif