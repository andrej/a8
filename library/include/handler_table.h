#ifndef HANDLER_TABLE_H
#define HANDLER_TABLE_H

#include <sys/syscall.h> // syscall numbers
#include "unknown_syscalls.h"
#include "handlers.h"

SYSCALL_ENTER_PROT(default_checked);
SYSCALL_ENTER_PROT(default_checked_arg1);
SYSCALL_ENTER_PROT(default_arg1_fd);
SYSCALL_ENTER_PROT(default_unchecked);
SYSCALL_EXIT_PROT(default_free_scratch);
SYSCALL_EXIT_PROT(default_creates_fd_exit);

#define SYSCALLS(X) \
/* ************************************************************************* *\
 * Syscall Handler Definitions                                               *\
 *  number,        name,        enter,                                       *\
 *                              post_call,                                   *\
 *                              exit                                         *\
 * ************************************************************************* */\
 X( __NR_brk,      brk,         SYSCALL_ENTER(brk), \
                                NULL, \
                                NULL ) \
 X( __NR_uname,    uname,       SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) \
 X( __NR_access,   access,      SYSCALL_ENTER(access), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_faccessat, faccessat,  SYSCALL_ENTER(faccessat), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_open,     open,        SYSCALL_ENTER(open), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) \
 X( __NR_openat,   openat,      SYSCALL_ENTER(openat), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) \
 X( __NR_close,    close,       SYSCALL_ENTER(close), \
                                NULL, \
                                SYSCALL_EXIT(close) ) \
 X( __NR_mmap,     mmap,        SYSCALL_ENTER(mmap), \
                                NULL, \
                                NULL ) \
 X( __NR_munmap,   munmap,      SYSCALL_ENTER(munmap), \
                                NULL, \
                                NULL ) \
 X( __NR_mprotect, mprotect,    SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_getpid,   getpid,      SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL  ) \
 X( __NR_getppid,  getppid,     SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) \
 X( __NR_read,     read,        SYSCALL_ENTER(read), \
                                NULL, \
                                SYSCALL_EXIT(read) ) \
 X( __NR_readv,    readv,       SYSCALL_ENTER(readv), \
                                NULL, \
                                SYSCALL_EXIT(readv) ) \
 X( __NR_write,    write,       SYSCALL_ENTER(write), \
                                NULL, \
                                SYSCALL_EXIT(write) ) \
 X( __NR_writev,   writev,      SYSCALL_ENTER(writev), \
                                NULL, \
                                SYSCALL_EXIT(writev) ) \
 X( __NR_stat,     stat,        SYSCALL_ENTER(stat), \
                                SYSCALL_POST_CALL(fstatat), \
                                SYSCALL_EXIT(stat)) \
 X( __NR_fstat,    fstat,       SYSCALL_ENTER(fstat), \
                                SYSCALL_POST_CALL(fstat), \
                                SYSCALL_EXIT(fstat)) \
 X( __NR_newfstatat, fstatat,   SYSCALL_ENTER(fstatat), \
                                SYSCALL_POST_CALL(fstatat), \
                                SYSCALL_EXIT(fstatat)) \
 X( __NR_getuid,   getuid,      SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_geteuid,  geteuid,     SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_getgid,   getgid,      SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_getegid,  getegid,     SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_setuid,   setuid,      SYSCALL_ENTER(default_checked_arg1), \
                                NULL, \
                                NULL) \
 X( __NR_setgid,   setgid,      SYSCALL_ENTER(default_checked_arg1), \
                                NULL, \
                                NULL) \
 X( __NR_getgroups,getgroups,   SYSCALL_ENTER(getgroups), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch)) \
 X( __NR_setgroups,setgroups,   SYSCALL_ENTER(setgroups), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_time,     time,        SYSCALL_ENTER(time), \
                                NULL, \
                                SYSCALL_EXIT(time)) \
 X( __NR_gettimeofday, gettimeofday, SYSCALL_ENTER(gettimeofday), \
                                NULL, \
                                SYSCALL_EXIT(gettimeofday)) \
 X( __NR_dup2,     dup2,        SYSCALL_ENTER(dup2), \
                                NULL, \
                                SYSCALL_EXIT(dup2)) \
 X( __NR_dup3,     dup3,        SYSCALL_ENTER(dup3), \
                                NULL, \
                                SYSCALL_EXIT(dup3)) \
 X( __NR_lseek,    lseek,       SYSCALL_ENTER(lseek),\
                                NULL, \
                                NULL) \
 X( __NR_getcwd,   getcwd,      SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) /* TODO */ \
 X( __NR_prlimit64,prlimit64,   SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) /* TODO */ \
 X( __NR_socket,   socket,      SYSCALL_ENTER(socket), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) \
 X( __NR_getsockopt,getsockopt, SYSCALL_ENTER(getsockopt), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_setsockopt,setsockopt, SYSCALL_ENTER(setsockopt), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_fcntl,    fcntl,       SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_connect,  connect,     SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_bind,     bind,        SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_listen,   listen,      SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_epoll_create, epoll_create, SYSCALL_ENTER(epoll_create), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) \
 X( __NR_epoll_create1, epoll_create1, SYSCALL_ENTER(epoll_create1), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) \
 X( __NR_epoll_ctl,epoll_ctl,   SYSCALL_ENTER(epoll_ctl), \
                                NULL, \
                                SYSCALL_EXIT(epoll_ctl) ) \
 X( __NR_epoll_wait,epoll_wait, SYSCALL_ENTER(epoll_wait), \
                                SYSCALL_POST_CALL(epoll_pwait), \
                                SYSCALL_EXIT(epoll_pwait) ) \
 X( __NR_epoll_pwait,epoll_pwait,SYSCALL_ENTER(epoll_pwait), \
                                SYSCALL_POST_CALL(epoll_pwait), \
                                SYSCALL_EXIT(epoll_pwait) ) \
 X( __NR_accept4,  accept4,     SYSCALL_ENTER(accept4), \
                                NULL, \
                                SYSCALL_EXIT(default_creates_fd_exit) ) /*TODO*/ \
 X( __NR_shutdown, shutdown,    SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL) /*TODO*/ \
 X( __NR_rt_sigaction, rt_sigaction, SYSCALL_ENTER(default_checked_arg1), \
                                NULL, \
                                NULL) /*TODO*/ \
 X( __NR_rt_sigprocmask, rt_sigprocmask, SYSCALL_ENTER(rt_sigprocmask), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch)) \
 X( __NR_ioctl,    ioctl,       SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL) /*TODO*/\
 X( __NR_recvfrom, recvfrom,    SYSCALL_ENTER(default_arg1_fd), \
                                NULL, \
                                NULL) /*TODO*/\
 X( __NR_sendfile, sendfile,    SYSCALL_ENTER(sendfile), \
                                NULL, \
                                NULL) \
 X( __NR_getrlimit, getrlimit,  SYSCALL_ENTER(getrlimit), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_setrlimit, setrlimit,  SYSCALL_ENTER(setrlimit), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch) ) \
 X( __NR_getsockname, getsockname,  SYSCALL_ENTER(getsockname), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch)) \
 X( __NR_getpeername, getpeername,  SYSCALL_ENTER(getsockname), \
                                NULL, \
                                SYSCALL_EXIT(default_free_scratch)) /* TODO */ \
 X( __NR_exit,      exit,       SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_exit_group, exit_group, SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 
#include "handler_table_prototypes.h"


#endif