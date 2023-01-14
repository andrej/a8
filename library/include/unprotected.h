#ifndef UNPROTECTED_H
#define UNPROTECTED_H

/* Since the PLT is inside the protected monitor, unprotected code cannot
   indirectly call other functions through the PLT (it would lead to a 
   segfault).
   
   Instead, we initialize a structure of "unprotected_funcs" upon library
   initialization (when all code is still unprotected) which contains direct 
   function pointers to other unprotected functions. Through this, an
   unprotected function can call other unprotected functions without causing
   memory access violations while the rest of the monitor is memory-protected.
   */

struct unprotected_funcs {

	// syscall.h
	long (* syscall)(long, long, long, long, long, long, long);

};

extern struct unprotected_funcs
unprotected_funcs;

void 
__attribute__((section("unprotected")))
init_unprotected();

#endif