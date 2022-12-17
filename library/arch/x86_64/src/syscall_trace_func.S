.text

	.globl monmod_syscall_trace_enter;
	.align 4, 0x90;
monmod_syscall_trace_enter:
	/* In SysV ABI, kernel destroys %rcx and %r11; hence these are the only
	   registers we may use without restoring them after exit to
	   properly emulate a syscall; the call site might depend on the other
	   registers. */

	movq %rsp, %r11

	/* store user_regs_struct */
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
	pushq 8(%r11) /* rip = ret_addr */
	pushq 0(%r11) /* orig_rax = syscall_no */
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %rax
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	movq %rsp, %rdi
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
	popq %rax
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
	
	/* return to orignial call site passed to us by kernel */
	jmpq *%rcx
