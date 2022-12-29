#ifndef CUSTOM_SYSCALLS_H
#define CUSTOM_SYSCALLS_H

// MAX_SYSCALL_NO == 325
//  #define __NR_monmod_init      (MAX_SYSCALL_NO+3)
//  #define __NR_monmod_reprotect (MAX_SYSCALL_NO+4)
// FIXME

#define __NR_monmod_init        328
#define __NR_monmod_reprotect   329

#endif