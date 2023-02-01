#include <stdlib.h>
#include "util.h"
#include "init.h"

void __attribute__((constructor)) monmod_do_init() 
{
	long ret = 0;
	monmod_library_init();
	asm volatile
	   ("ldp x29, x30, [x29]\n\t" 
	    "mov sp, x29\n\t"
	    "mov x8, 329\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "mov x0, 0\n\t" /* arg 0: write_back */
	    "mov x1, x30\n\t" /* arg 1: return addr from link register */
	    "svc 0x0\n\t"
	    "mov x0, %0"
	  : "=rm" (ret)
	  : 
	  : "memory" );
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}


void __attribute__ ((section ("unprotected")))
monmod_unprotected_reprotect()
{
	long ret = 0;
	asm volatile
	   ("ldp x29, x30, [x29]\n\t" 
	    "mov sp, x29\n\t"
	    "mov x8, 329\n\t" /* FIXME hardcoded __NR_monmod_reprotect */
	    "mov x0, 0\n\t" /* arg 0: write_back */
	    "mov x1, x30\n\t" /* arg 1: return addr from link register */
	    "svc 0x0\n\t"
	    "mov x0, %0"
	  : "=rm" (ret)
	  : 
	  : "memory" );
	WARNF("Reprotect failed with return value %ld.\n", ret);
	exit(1);
}