#ifndef UNPROTECTED_H
#define UNPROTECTED_H

#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <signal.h>

/* The following two are defined in the main.lds linker script and capture the
   start and end address of any functions marked section("unprotected").
   Functions in this section will remain accessible even when the rest of the
   monitor is memory-protected. */
extern char __unprotected_start;
extern char __unprotected_end;

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

	// monmod_syscall.h
	long (* syscall)(long, long, long, long, long, long, long);

   // unistd.h
   pid_t (* fork)(void);
   pid_t (* getpid)(void);
   typeof(getppid) *getppid;
   typeof(usleep) *usleep;
   typeof(close) *close;
   typeof(dup) *dup;

   // string.h
   typeof(memcpy) *memcpy;

   // <sys/mman.h>
   typeof(mprotect) *mprotect;

   // semaphore.h
   typeof(sem_wait) *sem_wait;
   typeof(sem_post) *sem_post;

   // stdlib.h
   typeof(exit) *exit;

   // sys/epoll.h
   typeof(epoll_create1) *epoll_create1;
   typeof(epoll_ctl) *epoll_ctl;

   // signal.h
   typeof(kill) *kill;
   typeof(waitpid) *waitpid;
   typeof(sigemptyset) *sigemptyset;
   typeof(sigaddset) *sigaddset;
   typeof(sigwait) *sigwait;

};

extern struct unprotected_funcs
unprotected_funcs;

void 
__attribute__((section("unprotected")))
init_unprotected();

#endif