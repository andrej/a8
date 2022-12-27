#include "custom_syscalls.h"

.text

	.globl monmod_syscall_trace_enter;
	.align 4, 0x90;
monmod_syscall_trace_enter:
	/* In SysV ABI, kernel destroys %rcx and %r11; hence these are the only
	   registers we may use without restoring them after exit to
	   properly emulate a syscall; the call site might depend on the other
	   registers. */

	/* This is entered with a struct syscall_trace_func_stack on top of the
	   stack. Remember %rsp in %r11 as a pointer to the beginning of that
	   structure. See kernel module code for layout of this struct. */
	movq %rsp, %r11

	/* store user_regs_struct on stack */
	pushq $0 /* FIXME %gs */
	pushq $0 /* FIXME %fs */
	pushq $0 /* FIXME %es */
	pushq $0 /* FIXME %ds */
	pushq $0 /* %gs_base */
	pushq $0 /* %fs_base */
	pushq $0 /* FIXME %ss */
	pushq %rsp
	pushfq /* eflags */
	pushq $0 /* FIXME %cs */
	pushq 40(%r11) /* rip = syscall_trace_func_stack->ret_addr */
	pushq 0(%r11) /* orig_rax = syscall_trace_func_stack->orig_syscall_no */
	pushq 8(%r11) /* rdi = syscall_trace_func_stack->orig_arg_0 */
	pushq 16(%r11) /* rsi = syscall_trace_func_stack->orig_arg_1 */
	pushq 24(%r11) /* rdx = syscall_trace_func_stack->orig_arg_2 */
	pushq %rcx
	pushq $0 /* %rax (going to be used for return value) */
	pushq %r8
	pushq %r9
	pushq 32(%r11) /* r10 = syscall_trace_func_stack->orig_arg_3 */
	pushq %r11
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	movq %rsp, %rdi /* pointer to struct syscall_trace_func_args in arg 1 */
	callq monmod_syscall_handle

	/* load user_regs_struct */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	addq $8, %rsp /* r11 -- gets destroyed later */
	popq %r10
	popq %r9
	popq %r8
	addq $8, %rsp /* rax -- keep monmod_syscall_handle() return as 
	                 syscall return value */
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
	addq $16, %rsp /* orig_rax, rip */
	addq $8, %rsp
	popq %r11 /* eflags */
	addq $64, %rsp /* rsp, ss, fs_base, gs_base, ds, es, fs, gs */

	/* remove remaining arguments from stack */
	addq $8, %rsp  /* syscall_no */
	popq %rcx /* ret_addr */
	addq $128, %rsp  /* redzone buffer added by kernel module */

	/* restore eflags; no arithmetic after this or flags will be wrong */
	pushq %r11 /* FIXME this destroys top of stack if red zone used */
	popfq
	
	/* return to orignial call site passed to us by kernel by issuing a
	   monmod_reprotect system call.
	   this call requires a struct syscall_trace_func_stack on the stack */
	pushq %rcx /* ret_addr */
	pushq %r10 /* orig_arg_3 */
	pushq %rdx /* orig_arg_2 */
	pushq %rsi /* orig_arg_1 */
	pushq %rdi /* orig_arg_0 */
	pushq %rax /* rax goes into orig_syscall_no; call site will interpret
	              this as the return value */
	movq %rdi, __NR_monmod_reprotect /* argument 0: syscall no */
	movq %rsi, %rsp /* argument 1: struct syscall_trace_func_stack */
	syscall
	/* unreachable */
