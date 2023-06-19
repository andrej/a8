#ifndef UNKNOWN_SYSCALLS_H
#define UNKNOWN_SYSCALLS_H

#include "arch.h"

/* This file defines __NR_xxx macros for system calls that are not available 
   on this architecture. */

#define __NR_UNKNOWN_SYSCALL (MAX_SYSCALL_NO+1)

#define __NR_access         __NR_UNKNOWN_SYSCALL
#define __NR_open           __NR_UNKNOWN_SYSCALL
#define __NR_stat           __NR_UNKNOWN_SYSCALL
#define __NR_time           __NR_UNKNOWN_SYSCALL
#define __NR_dup2           __NR_UNKNOWN_SYSCALL
#define __NR_epoll_create   __NR_UNKNOWN_SYSCALL
#define __NR_epoll_wait     __NR_UNKNOWN_SYSCALL
#define __NR_pread          __NR_UNKNOWN_SYSCALL
#define __NR_pwrite         __NR_UNKNOWN_SYSCALL
#define __NR_mkdir          __NR_UNKNOWN_SYSCALL
#define __NR_fork           __NR_UNKNOWN_SYSCALL
#define __NR_wait           __NR_UNKNOWN_SYSCALL
#define __NR_waitpid        __NR_UNKNOWN_SYSCALL
#define __NR_wait3          __NR_UNKNOWN_SYSCALL
#define __NR_readlink       __NR_UNKNOWN_SYSCALL
#define __NR_pipe           __NR_UNKNOWN_SYSCALL
#define __NR_rename         __NR_UNKNOWN_SYSCALL
#define __NR_unlink         __NR_UNKNOWN_SYSCALL

#endif
