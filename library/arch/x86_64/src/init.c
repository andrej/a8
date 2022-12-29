#include <stdlib.h>
#include "util.h"
#include "init.h"

void __attribute__((constructor)) monmod_do_init() 
{
	long ret = 0;
	monmod_library_init();
	// TODO separate arch specific code
	asm("leaveq\n\t"
	    "movq $329, %%rax\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "movq $0, %%rdi\n\t" /* arg 0 %rdi: write_back */
	    "popq %%rsi\n\t" /* arg 1 %rsi: pop return addr */
	    "syscall\n\t"
	    "movq %%rax, %0"
	  : "=rm" (ret));
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}
