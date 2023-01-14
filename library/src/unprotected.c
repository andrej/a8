#include "unprotected.h"
#include "checkpointing.h"
#include "syscall.h"

struct unprotected_funcs
unprotected_funcs = {};

void 
__attribute__((section("unprotected")))
init_unprotected()
{
	unprotected_funcs.syscall = monmod_untrusted_syscall;
}
