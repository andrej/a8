#ifndef HANDLER_TABLE_H
#define HANDLER_TABLE_H

#include <sys/syscall.h> // syscall numbers
#include "unknown_syscalls.h"
#include "handlers.h"

SYSCALL_ENTER_PROT(default_checked);
SYSCALL_ENTER_PROT(default_checked_arg1);
SYSCALL_ENTER_PROT(default_arg1_fd);
SYSCALL_EXIT_PROT(default_creates_fd);


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
                                SYSCALL_EXIT(access) ) \
 X( __NR_faccessat, faccessat,  SYSCALL_ENTER(faccessat), \
                                NULL, \
                                SYSCALL_EXIT(faccessat) ) \
 X( __NR_open,     open,        SYSCALL_ENTER(open), \
                                NULL, \
                                SYSCALL_EXIT(open) ) \
 X( __NR_openat,   openat,      SYSCALL_ENTER(openat), \
                                NULL, \
                                SYSCALL_EXIT(openat) ) \
 X( __NR_close,    close,       SYSCALL_ENTER(close), \
                                NULL, \
                                SYSCALL_EXIT(close) ) \
 X( __NR_mmap,     mmap,        SYSCALL_ENTER(mmap), \
                                NULL, \
                                NULL ) \
 X( __NR_munmap,   munmap,      SYSCALL_ENTER(munmap), \
                                NULL, \
                                NULL ) \
 X( __NR_mprotect, mprotect,    SYSCALL_ENTER(mprotect), \
                                NULL, \
                                NULL ) /*TODO*/ \
 X( __NR_read,     read,        SYSCALL_ENTER(read), \
                                NULL, \
                                SYSCALL_EXIT(read) ) \
 X( __NR_pread,    pread,       SYSCALL_ENTER(pread), \
                                NULL, \
                                SYSCALL_EXIT(pread) ) \
 X( __NR_pread64,  pread64,     SYSCALL_ENTER(pread), \
                                NULL, \
                                SYSCALL_EXIT(pread) ) \
 X( __NR_readv,    readv,       SYSCALL_ENTER(readv), \
                                NULL, \
                                SYSCALL_EXIT(readv) ) \
 X( __NR_write,    write,       SYSCALL_ENTER(write), \
                                NULL, \
                                SYSCALL_EXIT(write) ) \
 X( __NR_pwrite,   pwrite,      SYSCALL_ENTER(pwrite), \
                                NULL, \
                                SYSCALL_EXIT(pwrite) ) \
 X( __NR_pwrite64, pwrite64,     SYSCALL_ENTER(pwrite), \
                                NULL, \
                                SYSCALL_EXIT(pwrite) ) \
 X( __NR_writev,   writev,      SYSCALL_ENTER(writev), \
                                NULL, \
                                SYSCALL_EXIT(writev) ) \
 X( __NR_stat,     stat,        SYSCALL_ENTER(stat), \
                                SYSCALL_POST_CALL(stat), \
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
                                SYSCALL_EXIT(getgroups)) \
 X( __NR_setgroups,setgroups,   SYSCALL_ENTER(setgroups), \
                                NULL, \
                                SYSCALL_EXIT(setgroups) ) \
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
                                SYSCALL_EXIT(socket) ) \
 X( __NR_socketpair,socketpair, SYSCALL_ENTER(socketpair), \
                                NULL, \
                                SYSCALL_EXIT(socketpair) ) \
 X( __NR_getsockopt,getsockopt, SYSCALL_ENTER(getsockopt), \
                                NULL, \
                                SYSCALL_EXIT(getsockopt) ) \
 X( __NR_setsockopt,setsockopt, SYSCALL_ENTER(setsockopt), \
                                NULL, \
                                SYSCALL_EXIT(setsockopt) ) \
 X( __NR_fcntl,    fcntl,       SYSCALL_ENTER(fcntl), \
                                NULL, \
                                SYSCALL_EXIT(fcntl) ) /*TODO*/ \
 X( __NR_connect,  connect,     SYSCALL_ENTER(connect), \
                                NULL, \
                                SYSCALL_EXIT(connect) ) /*TODO*/ \
 X( __NR_bind,     bind,        SYSCALL_ENTER(bind), \
                                NULL, \
                                SYSCALL_EXIT(bind) ) /*TODO*/ \
 X( __NR_listen,   listen,      SYSCALL_ENTER(listen), \
                                NULL, \
                                SYSCALL_EXIT(listen) ) /*TODO*/ \
 X( __NR_epoll_create,epoll_create, SYSCALL_ENTER(epoll_create), \
                                NULL, \
                                SYSCALL_EXIT(epoll_create) ) \
 X( __NR_epoll_create1,epoll_create1, SYSCALL_ENTER(epoll_create1), \
                                NULL, \
                                SYSCALL_EXIT(epoll_create1) ) \
 X( __NR_epoll_ctl,epoll_ctl,   SYSCALL_ENTER(epoll_ctl), \
                                NULL, \
                                SYSCALL_EXIT(epoll_ctl) ) \
 X( __NR_epoll_wait,epoll_wait, SYSCALL_ENTER(epoll_wait), \
                                SYSCALL_POST_CALL(epoll_pwait), \
                                SYSCALL_EXIT(epoll_pwait) ) \
 X( __NR_epoll_pwait,epoll_pwait,SYSCALL_ENTER(epoll_pwait), \
                                SYSCALL_POST_CALL(epoll_pwait), \
                                SYSCALL_EXIT(epoll_pwait) ) \
 X( __NR_eventfd2, eventfd2,    SYSCALL_ENTER(eventfd2), \
                                NULL, \
                                SYSCALL_EXIT(eventfd2)) \
 X( __NR_accept4,  accept4,     SYSCALL_ENTER(accept4), \
                                NULL, \
                                SYSCALL_EXIT(accept4) ) /*TODO*/ \
 X( __NR_shutdown, shutdown,    SYSCALL_ENTER(shutdown), \
                                NULL, \
                                SYSCALL_EXIT(shutdown)) /*TODO*/ \
 X( __NR_rt_sigaction, rt_sigaction, SYSCALL_ENTER(default_checked_arg1), \
                                NULL, \
                                NULL) /*TODO*/ \
 X( __NR_rt_sigprocmask, rt_sigprocmask, SYSCALL_ENTER(rt_sigprocmask), \
                                NULL, \
                                SYSCALL_EXIT(rt_sigprocmask)) \
 X( __NR_ioctl,    ioctl,       SYSCALL_ENTER(ioctl), \
                                NULL, \
                                SYSCALL_EXIT(ioctl)) /*TODO*/\
 X( __NR_recvfrom, recvfrom,    SYSCALL_ENTER(recvfrom), \
                                NULL, \
                                SYSCALL_EXIT(recvfrom)) /*TODO*/\
 X( __NR_sendfile, sendfile,    SYSCALL_ENTER(sendfile), \
                                NULL, \
                                SYSCALL_EXIT(sendfile)) \
 X( __NR_getrlimit, getrlimit,  SYSCALL_ENTER(getrlimit), \
                                NULL, \
                                SYSCALL_EXIT(getrlimit) ) \
 X( __NR_setrlimit, setrlimit,  SYSCALL_ENTER(setrlimit), \
                                NULL, \
                                SYSCALL_EXIT(setrlimit) ) \
 X( __NR_getsockname, getsockname,  SYSCALL_ENTER(getsockname), \
                                NULL, \
                                SYSCALL_EXIT(getsockname)) \
 X( __NR_getpeername, getpeername,  SYSCALL_ENTER(getsockname), \
                                NULL, \
                                SYSCALL_EXIT(getsockname)) /* TODO */ \
 X( __NR_sendmsg,   sendmsg,    SYSCALL_ENTER(sendmsg), \
                                NULL, \
                                SYSCALL_EXIT(sendmsg)) \
 X( __NR_exit,      exit,       SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_exit_group, exit_group, SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL) \
 X( __NR_sched_yield, sched_yield, SYSCALL_ENTER(default_checked), \
                                NULL, \
                                NULL ) \
 X( __NR_mkdir,     mkdir,      SYSCALL_ENTER(mkdir), \
                                NULL, \
                                SYSCALL_EXIT(mkdir) ) \
 X( __NR_mkdirat,   mkdirat,    SYSCALL_ENTER(mkdirat), \
                                NULL, \
                                SYSCALL_EXIT(mkdirat) ) \
 X( __NR_getpid,    getpid,     SYSCALL_ENTER(getpid), \
                                NULL, \
                                NULL ) \
 X( __NR_getppid,   getppid,    SYSCALL_ENTER(getppid), \
                                NULL, \
                                NULL ) \
 X( __NR_fork,      fork,       SYSCALL_ENTER(fork), \
                                NULL, \
                                SYSCALL_EXIT(fork) ) \
 X( __NR_clone,     clone,      SYSCALL_ENTER(clone), \
                                NULL, \
                                SYSCALL_EXIT(clone) ) \
 X( __NR_wait,      wait,       SYSCALL_ENTER(wait), \
                                NULL, \
                                SYSCALL_EXIT(wait) ) \
 X( __NR_waitpid,   waitpid,    SYSCALL_ENTER(waitpid), \
                                NULL, \
                                SYSCALL_EXIT(waitpid) ) \
 X( __NR_wait3,     wait3,      SYSCALL_ENTER(wait3), \
                                NULL, \
                                SYSCALL_EXIT(wait3) ) \
 X( __NR_wait4,     wait4,      SYSCALL_ENTER(wait4), \
                                NULL, \
                                SYSCALL_EXIT(wait4) ) \
 
#include "handler_table_prototypes.h"


#endif