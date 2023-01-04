#include <stdlib.h>
#include "util.h"
#include "init.h"

void __attribute__((constructor)) monmod_do_init() 
{
	long ret = 0;
	monmod_library_init();
	// TODO separate arch specific code
	asm volatile
	   ("ldp x29, x30, [sp],#32\n\t" /* FIXME hardcoded sp offset;  this
	                                    is informed by the stack allocated
					    by gcc for this function, and will 
					    change if we add variables etc ...
					    unstable! */
	    "mov x8, 329\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "mov x0, 0\n\t" /* arg 0: write_back */
	    "mov x1, x30\n\t" /* arg 1: return addr from link register */
	    "svc 0x0\n\t"
	    "mov x0, %0"
	  : "=rm" (ret)
	  : 
	  : "sp", "x28", "x8", "x0", "x1", "x30", "memory" );
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}
