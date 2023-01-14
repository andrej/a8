#define EXPORT(name)           \
        .globl name;           \
	name:

#define ENTRY(name)            \
	.globl name;           \
	.type name, @function; \
	.align 4, 0x90;        \
	name:

.macro syscall_prep_instrs
	movq %rdi, %rax 
	movq %rsi, %rdi
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10 
	movq %r9, %r8
	movq 8(%rsp), %r9
.endm

	.text
ENTRY(monmod_trusted_syscall)
	syscall_prep_instrs
	syscall
EXPORT(monmod_syscall_trusted_addr)
	ret  # return raw syscall return value in %rax

	.section unprotected,"ax",@progbits
ENTRY(monmod_untrusted_syscall)
	syscall_prep_instrs
	syscall
	ret
