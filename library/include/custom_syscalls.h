#ifndef CUSTOM_SYSCALLS_H
#define CUSTOM_SYCALLS_H

#include <unistd.h>
#include <sys/syscall.h>
#include "custom_syscall_api.h"

int monmod_exit(int code);

int monmod_init(pid_t pid, 
                void *trusted_syscall_addr, void *monitor_enter_addr,
                void *overall_start, size_t overall_len,
                void *code_start, size_t code_len,
                void *protected_data_start, size_t protected_data_len);

int monmod_destroy();

#endif