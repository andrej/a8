#ifndef HANDLER_TABLE_H
#define HANDLER_TABLE_H

#include <sys/syscall.h> // syscall numbers
#include "handlers.h"

SYSCALL_ENTER_PROT(default_checked);
SYSCALL_ENTER_PROT(default_arg1_fd);
SYSCALL_ENTER_PROT(default_unchecked);


#define SYSCALLS(X) \
/* ************************************************************************* *\
 * Syscall Handler Definitions                                               *\
 *  number,        name,       enter,                  exit                  *\
 * ************************************************************************* */\
 X( __NR_brk,      brk,        SYSCALL_ENTER(brk),     NULL ) \
 X( __NR_uname,    uname,      SYSCALL_ENTER(default_checked), NULL ) \
 X( __NR_access,   access,     SYSCALL_ENTER(access),  SYSCALL_EXIT(access) ) \
 X( __NR_open,     open,       SYSCALL_ENTER(open),    SYSCALL_EXIT(openat) ) \
 X( __NR_openat,   openat,     SYSCALL_ENTER(openat),  SYSCALL_EXIT(openat) ) \
 X( __NR_close,    close,      SYSCALL_ENTER(close),   SYSCALL_EXIT(close) ) \
 X( __NR_mmap,     mmap,       SYSCALL_ENTER(mmap),    NULL ) \
 X( __NR_munmap,   munmap,     SYSCALL_ENTER(munmap),  NULL ) \
 X( __NR_mprotect, mprotect,   SYSCALL_ENTER(default_checked), NULL ) /*TODO*/ \
 X( __NR_getpid,   getpid,     SYSCALL_ENTER(default_checked), NULL  ) \
 X( __NR_read,     read,       SYSCALL_ENTER(read),    SYSCALL_EXIT(read) ) \
 X( __NR_readv,    readv,      SYSCALL_ENTER(readv),   SYSCALL_EXIT(readv) ) \
 X( __NR_write,    write,      SYSCALL_ENTER(write),   SYSCALL_EXIT(write) ) \
 X( __NR_writev,   writev,     SYSCALL_ENTER(writev),  SYSCALL_EXIT(writev) ) \
 X( __NR_stat,     stat,       SYSCALL_ENTER(stat),    SYSCALL_EXIT(stat) ) \
 X( __NR_fstat,    fstat,      SYSCALL_ENTER(fstat),   SYSCALL_EXIT(fstat) ) \
 X( __NR_getuid,   getuid,     SYSCALL_ENTER(default_checked), NULL) \
 X( __NR_geteuid,  geteuid,    SYSCALL_ENTER(default_checked), NULL) \
 X( __NR_time,     time,       SYSCALL_ENTER(time),    SYSCALL_EXIT(time)) \
 X( __NR_gettimeofday, gettimeofday, SYSCALL_ENTER(gettimeofday), \
                               SYSCALL_EXIT(gettimeofday)) \
 X( __NR_dup2,     dup2,       SYSCALL_ENTER(dup2),    SYSCALL_EXIT(dup2)) \
 X( __NR_lseek,    lseek,      SYSCALL_ENTER(lseek),   NULL) \
 X( __NR_getcwd,   getcwd,     SYSCALL_ENTER(default_checked), NULL ) /* TODO */ \
 X( __NR_prlimit64,prlimit64,  SYSCALL_ENTER(default_checked), NULL ) /* TODO */ \
 X( __NR_socket,   socket,     SYSCALL_ENTER(socket),  SYSCALL_EXIT(socket)) /*TODO*/ \
 X( __NR_setsockopt,setsockopt,SYSCALL_ENTER(default_arg1_fd), NULL ) /*TODO*/ \
 X( __NR_fcntl,    fcntl,      SYSCALL_ENTER(default_arg1_fd), NULL ) /*TODO*/ \
 X( __NR_connect,  connect,    SYSCALL_ENTER(default_arg1_fd), NULL ) /*TODO*/ \
 X( __NR_bind,     bind,       SYSCALL_ENTER(default_arg1_fd), NULL ) /*TODO*/ \
 X( __NR_listen,   listen,     SYSCALL_ENTER(default_arg1_fd), NULL ) /*TODO*/ \
 X( __NR_epoll_create, epoll_create, SYSCALL_ENTER(default_checked), \
                               SYSCALL_EXIT(epoll_create)) \
 X( __NR_epoll_ctl,epoll_ctl,  SYSCALL_ENTER(epoll_ctl),SYSCALL_EXIT(epoll_ctl) ) \
 X( __NR_epoll_wait, epoll_wait, SYSCALL_ENTER(epoll_wait), \
                               SYSCALL_EXIT(epoll_wait)) \



#include "handler_table_prototypes.h"

/*
syscall				modifies fd?	needs fd? 	needs sync?
execve				no		no
brk(NULL)			no		no
uname				no		no
faccessat			no		no		yes
openat				yes		no		yes
fstat				no		yes		yes
mmap				no		yes
close				yes		yes
read				no		yes		yes
mprotect			no		no
munmap				no		no
getuid				no		no
geteuid				no		no
getegid				no		no
getgid				no		no
gettimeofday			no		no		yes
getpid				no		no		yes
dup3				yes		yes		no?
newfstatat			no		no		yes
prlimit64			no		no		no
socket				yes		no		yes
fcntl				no		yes		no
setsockopt			no		yes		no
bind				no		yes		no
listen				no		yes		no
rt_sigaction			no		no		no
lseek				no		yes		no
write				no		yes		yes
epoll_create1			yes		yes		no
epoll_ctl			no		yes		no
epoll_pwait			no		yes		yes
accept4				yes		yes		yes
getsockopt			no		yes		yes
ioctl				no		yes		yes
writev				no		yes		yes
shutdown			yes		yes		yes
recvfrom			no		yes		yes
*/

#endif