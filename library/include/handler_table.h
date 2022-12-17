#ifndef HANDLER_TABLE_H
#define HANDLER_TABLE_H

#include <sys/syscall.h> // syscall numbers
#include "handlers.h"

SYSCALL_ENTER_PROT(default);
SYSCALL_EXIT_PROT(default);

#define SYSCALLS(X) \
/* ************************************************************************* *\
 * Syscall Handler Definitions                                               *\
 *  number,        name,       enter,                  exit                  *\
 *                             get_arg_types,                                *\
 *                             free_arg_types                                *\
 * ************************************************************************* */\
 X( __NR_brk,      brk,        SYSCALL_ENTER(brk),     NULL, \
                               NULL, \
			       NULL) \
 X( __NR_uname,    uname,      SYSCALL_ENTER(default), NULL, \
                               NULL, \
			       NULL) \
 X( __NR_access,   access,     SYSCALL_ENTER(default), NULL, \
                               NULL, \
			       NULL) \
 X( __NR_open,     open,       SYSCALL_ENTER(open),    SYSCALL_EXIT(open), \
                               NULL, \
			       NULL) \
 X( __NR_fstat,    fstat,      SYSCALL_ENTER(default), NULL, \
                               NULL, \
			       NULL) \
 X( __NR_mmap,     mmap,       NULL,    NULL, \
                               NULL, \
			       NULL) \
 X( __NR_getpid,   getpid,     SYSCALL_ENTER(default), NULL, \
                               NULL, \
			       NULL) \
 X( __NR_read,     read,       SYSCALL_ENTER(read),    SYSCALL_EXIT(read), \
                               NULL, \
			       NULL) \
 X( __NR_write,    write,      SYSCALL_ENTER(write),   NULL, \
                               NULL, \
			       NULL) \
 X( __NR_writev,   writev,     SYSCALL_ENTER(writev),  SYSCALL_EXIT(writev), \
 		               SYSCALL_GET_ARG_TYPES(writev),  \
			       SYSCALL_FREE_ARG_TYPES(writev)) \


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