#ifndef CUSTOM_SYSCALLS_H
#define CUSTOM_SYCALLS_H

#include <unistd.h>
#include <sys/syscall.h>
#include "custom_syscall_nrs.h"

int monmod_exit(int code);

int monmod_init(pid_t pid, void *monitor_start, size_t monitor_len,
                void *trusted_syscall_addr, void *monitor_enter_addr);

int monmod_init_unprotected(pid_t pid, void *monitor_start, size_t monitor_len,
                            void *trusted_syscall_addr, 
                            void *monitor_enter_addr);

int monmod_destroy();

#endif