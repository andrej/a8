#define __ALIGN	    .align 4, 0x90
#define ENTRY(name)            \
	.globl name;           \
	.type name, @function; \
	.align 4, 0x90;        \
	name:

	.text
ENTRY(monmod_syscall)
	movq %rdi, %rax  # Syscall no
	movq %rsi, %rdi
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp), %r9
	syscall
	ret  # return raw syscall return value in %rax
