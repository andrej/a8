#include <stdlib.h>
#include "util.h"
#include "init.h"

void __attribute__((constructor)) monmod_do_init() 
{
	long ret = 0;
	monmod_library_init();
	asm volatile
	   ("movq %%rbp, %%rsp\n\t" /* leaveq */
	    "pop %%rbp\n\t" /* leaveq */
	    "movq $329, %%rax\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "movq $0, %%rdi\n\t" /* arg 0 %rdi: write_back */
	    "popq %%rsi\n\t" /* arg 1 %rsi: return addr, popped from stack */
	    "syscall\n\t"
	    "movq %%rax, %0"
	  : "=rm" (ret)
	  : 
	  : "rsp", "rax", "rdi", "rsi", "memory");
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}

void __attribute__ ((section ("unprotected")))
monmod_unprotected_reprotect()
{
	long ret = 0;
	asm volatile
	   ("movq %%rbp, %%rsp\n\t" /* leaveq */
	    "pop %%rbp\n\t" /* leaveq */
	    "movq $329, %%rax\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "movq $0, %%rdi\n\t" /* arg 0 %rdi: write_back */
	    "popq %%rsi\n\t" /* arg 1 %rsi: return addr, popped from stack */
	    "syscall\n\t"
	    /* If any instructions past this get executed, the system call 
	       failed. A successful reprotect call will divert program execution
	       to the given return address. */
	    "movq %%rax, %0"
	  : "=rm" (ret)
	  : 
	  : "rsp", "rax", "rdi", "rsi", "memory");
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}