#ifndef SYSCALL_H
#define SYSCALL_H

extern void monmod_syscall_trusted_addr(void);

extern long monmod_trusted_syscall(long no, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long arg6);

#endif