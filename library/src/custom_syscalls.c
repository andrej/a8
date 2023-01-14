#include "custom_syscalls.h"
#include "syscall.h"

int monmod_exit(int code)
{
	return monmod_trusted_syscall(__NR_exit, code, 0, 0, 0, 0, 0);
}

int monmod_init(pid_t pid, void *monitor_start, size_t monitor_len,
                void *trusted_syscall_addr, void *monitor_enter_addr)
{
	int ret = monmod_trusted_syscall(__NR_monmod_init, pid, 
	                                 (long)monitor_start,
	                                 monitor_len, 
					 (long)trusted_syscall_addr,
					 (long)monitor_enter_addr,
					 0);
	return ret;
}