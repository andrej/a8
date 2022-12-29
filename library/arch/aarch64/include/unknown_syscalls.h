#ifndef UNKNOWN_SYSCALLS_H
#define UNKNOWN_SYSCALLS_H

#include "arch.h"

/* This file defines __NR_xxx macros for system calls that are not available 
   on this architecture. */

#define __NR_access         (MAX_SYSCALL_NO+1)
#define __NR_open           (MAX_SYSCALL_NO+1)
#define __NR_stat           (MAX_SYSCALL_NO+1)
#define __NR_time           (MAX_SYSCALL_NO+1)
#define __NR_dup2           (MAX_SYSCALL_NO+1)
#define __NR_epoll_create   (MAX_SYSCALL_NO+1)
#define __NR_epoll_wait     (MAX_SYSCALL_NO+1)

#endif
