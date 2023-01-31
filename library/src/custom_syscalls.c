#include "custom_syscalls.h"
#include "syscall.h"
#include "util.h"
#include "unprotected.h"

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

int 
__attribute__(( section("unprotected") ))
monmod_init_unprotected(pid_t pid, void *monitor_start, size_t monitor_len,
            void *trusted_syscall_addr, void *monitor_enter_addr)
{
	int ret = unprotected_funcs.syscall(__NR_monmod_init, pid, 
	                                    (long)monitor_start,
	                                    monitor_len, 
	                                    (long)trusted_syscall_addr,
	                                    (long)monitor_enter_addr,
	                                    0);
	return ret;
}

int monmod_destroy()
{
	int ret = monmod_trusted_syscall(__NR_monmod_destroy, getpid(),
	                                 0, 0, 0, 0, 0);
	if(0 != ret) {
		WARNF("monmod_destroy failed with return code %d.\n", ret);
		monmod_exit(2);
	}
	return 0; /* should never return; system call kills process*/
}
