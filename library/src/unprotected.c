#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>

#include "unprotected.h"
#include "checkpointing.h"
#include "monmod_syscall.h"
#include "custom_syscalls.h"
#include "library_init.h"
#include "monitor.h"

#undef sem_wait
#undef sem_post

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
	unprotected_funcs.dup = dup;
	unprotected_funcs.memcpy = memcpy;
	unprotected_funcs.mprotect = mprotect;
	unprotected_funcs.sem_wait = sem_wait;
	unprotected_funcs.sem_post = sem_post;
	unprotected_funcs.exit = exit;
	unprotected_funcs.epoll_create1 = epoll_create1;
	unprotected_funcs.epoll_ctl = epoll_ctl;
	unprotected_funcs.kill = kill;
	unprotected_funcs.waitpid = waitpid;
   	unprotected_funcs.sigemptyset = sigemptyset;
   	unprotected_funcs.sigaddset = sigaddset;
   	unprotected_funcs.sigwait = sigwait;
}
