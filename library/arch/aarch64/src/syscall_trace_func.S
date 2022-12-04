.text

	.globl syscall_trace_func;
	.align 4, 0x90;
syscall_trace_func:
	mov     x0,       sp
	add     x0, x0, #8
	bl trusted_area
	/* After returning from user-space syscall trace subroutine call, we 
	   must restore the state to appear unchanged to the syscall-site
	   as if we just returned from the kernel. 

	   This is inspired from .macro kernel_exit in entry.S. */
	ldr     x9,       [sp, #31 * 8 + 32]
	msr     nzcv,     x9
	ldr     x9,       [sp, #8] 
	/* do not restore x0 value; our callback should be able to dictate the
	   return value of the system call. */
	ldr	x1,       [sp, #16 * 0 + 16 + 8]
	ldp	x2, x3,   [sp, #16 * 1 + 16]
	ldp	x4, x5,   [sp, #16 * 2 + 16]
	ldp	x6, x7,   [sp, #16 * 3 + 16]
	/*ldp	x8, x9,   [sp, #16 * 4]*/
	ldr     x8,       [sp, #16 * 4 + 16]
	ldp	x10, x11, [sp, #16 * 5 + 16]
	ldp	x12, x13, [sp, #16 * 6 + 16]
	ldp	x14, x15, [sp, #16 * 7 + 16]
	ldp	x16, x17, [sp, #16 * 8 + 16]
	ldp	x18, x19, [sp, #16 * 9 + 16]
	ldp	x20, x21, [sp, #16 * 10 + 16]
	ldp	x22, x23, [sp, #16 * 11 + 16]
	ldp	x24, x25, [sp, #16 * 12 + 16]
	ldp	x26, x27, [sp, #16 * 13 + 16]
	ldp	x28, x29, [sp, #16 * 14 + 16]
	ldr     x30,      [sp, #16 * 15 + 16] /* restore link register */
	/*ldr	lr, [sp, #S_LR]*/
	add	sp, sp,   #320 + 128 /* 320 is size of our data on stack;
	                                128 is red zone buffer. */
	br 	x9  /* TODO ensure it is fine to loose x9! */
