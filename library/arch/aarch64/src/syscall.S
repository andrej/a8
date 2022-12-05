/* After glibc */
#define EXPORT(name)           \
        .globl name;           \
	name:

#define ENTRY(name)            \
	.globl name;           \
	.type name, @function; \
	name:

	.text
ENTRY(monmod_syscall)
	uxtw x8, w0  /* Sign-extend w0 (src) into x8 (dest) */
	mov x0, x1   /* move x1 (src) into x0 (dest) */
	mov x1, x2
	mov x2, x3
	mov x3, x4
	mov x4, x5
	mov x5, x6
	/* mov x6, x7 */
	mov x6, #0  /* for now we skip argument 7 ... no one seems to use it
	               and x86_64 only has 6 arguments */
	svc 0x0  /* syscall enter instruction */
EXPORT(monmod_syscall_trusted_addr)
	ret  /* return raw syscall return value in x0 */
