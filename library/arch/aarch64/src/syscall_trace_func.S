#include <sys/syscall.h>
#include "custom_syscall_nrs.h"

.text

	.globl monmod_syscall_trace_enter;
	.align 4, 0x90;
monmod_syscall_trace_enter:
	/* Pass struct syscall_trace_func_stack to monmod_syscall_handle. */
	mov x0, sp
	bl monmod_handle_syscall
	/* Write back return value to struct syscall_trace_func_stack. */
	str x0, [sp]
	mov x8, __NR_monmod_reprotect
	mov x0, 1
	mov x1, sp
	svc 0x0
	mov x8, __NR_exit
	mov x0, 2
	svc 0x0
