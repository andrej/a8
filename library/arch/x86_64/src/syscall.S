#define EXPORT(name)           \
        .globl name;           \
	name:

#define ENTRY(name)            \
	.globl name;           \
	.type name, @function; \
	.align 4, 0x90;        \
	name:

	.text
ENTRY(monmod_trusted_syscall)
	movq %rdi, %rax  # Syscall no
	movq %rsi, %rdi
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp), %r9
	syscall
EXPORT(monmod_syscall_trusted_addr)
	ret  # return raw syscall return value in %rax

ENTRY(monmod_untrusted_syscall)
	movq %rdi, %rax  # Syscall no
	movq %rsi, %rdi
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp), %r9
	syscall
EXPORT(monmod_syscall_untrusted_addr)
	ret  # return raw syscall return value in %rax
