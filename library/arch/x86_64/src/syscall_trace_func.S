.text

	.globl syscall_trace_func;
	.align 4, 0x90;
syscall_trace_func:
	movq %rsp, %rdi
	subq $8, %rdi
	callq trusted_area@PLT
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	addq $8, %rsp  /* r11 */
	popq %r10
	popq %r9
	popq %r8
	addq $16, %rsp /* rax */
	               /* rcx */
	popq %rdx
	popq %rsi
	popq %rdi
	addq $24, %rsp /* orig_rax */
	               /* rip */
	               /* cs */
	popq %r11      /* eflags */ 
	addq $16, %rsp /* rsp */

	popq %rcx /* In SysV ABI, the kernel destroys %rcx and %r11 on syscall, 
	            so a user application may not expect it to be preserved.
	            The kernel module passed return address on bottom of stack.
		    So after this %r12 = return address into libc, directly
		    after syscall instruction. */
	addq $128, %rsp /* Kernel module moved rsp to protect red zone. */
	andq $0xfffffffffffffeff, %r11 /* unset trap flag */
	pushq %r11
	popf /* Make sure there are no arithmetic operations after this as this 
	        would alter eflags. */
	jmpq *%rcx
