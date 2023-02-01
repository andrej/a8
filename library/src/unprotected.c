#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>

#include "unprotected.h"
#include "checkpointing.h"
#include "syscall.h"
#include "custom_syscalls.h"
#include "init.h"

struct unprotected_funcs
unprotected_funcs = {};

void 
__attribute__((section("unprotected")))
init_unprotected()
{
	unprotected_funcs.syscall = monmod_untrusted_syscall;
	unprotected_funcs.fork = fork;
	unprotected_funcs.getpid = getpid;
	unprotected_funcs.getppid = getppid;
	unprotected_funcs.usleep = usleep;
	unprotected_funcs.close = close;
	unprotected_funcs.memcpy = memcpy;
	unprotected_funcs.mprotect = mprotect;
	unprotected_funcs.monmod_init = monmod_init_unprotected;
	unprotected_funcs.monmod_unprotected_reprotect = 
		monmod_unprotected_reprotect;
	unprotected_funcs.sem_wait = sem_wait;
	unprotected_funcs.sem_post = sem_post;
	unprotected_funcs.exit = exit;
}
