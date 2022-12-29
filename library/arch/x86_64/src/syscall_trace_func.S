#include "custom_syscalls.h"

.text

	.globl monmod_syscall_trace_enter;
	.align 4, 0x90;
monmod_syscall_trace_enter:
	/* The kernel redirects execution to this address with a struct 
	   syscall_trace_func_stack on top of the stack and 128 bytes of 
	   padding to previous stack pointer. */

	movq %rsp, %rdi
	callq monmod_syscall_handle

	/* Return to the original system call site via the reprotect system
	   call. This system call takes the syscall_trace_func_stack pointer
	   as its argument and will restore those register values. 
	   
	   This includes the program counter register, hence it will redirect
	   back to the original call site.

	   The only register we change is the return value register.
	   */
	movq %rax, 80(%rsp) /* store new return value to overwrite in
	                        pt_regs->rax */
	movq $__NR_monmod_reprotect, %rax /* argument 0: syscall no */
	movq $1, %rdi /* argument 0: bool write_back */
	movq %rsp, %rsi /* argument 1: struct syscall_trace_func_stack */
	syscall
	/* we only reach this on error */
	movq $2, %rdi
	callq exit@plt

