#include "custom_syscalls.h"
#include "syscall.h"
#include "util.h"
#include "unprotected.h"

int monmod_exit(int code)
{
	return monmod_trusted_syscall(__NR_exit, code, 0, 0, 0, 0, 0);
}

int __attribute__((section("unprotected")))
monmod_init(pid_t pid, 
            void *trusted_syscall_addr, void *monitor_enter_addr,
            void *overall_start, size_t overall_len,
            void *code_start, size_t code_len,
            void *protected_data_start, size_t protected_data_len)
{
	struct monmod_monitor_addr_ranges addr_ranges = {
		.overall_start = overall_start,
		.overall_len = overall_len,
		.code_start = code_start,
		.code_len = code_len,
		.protected_data_start = protected_data_start,
		.protected_data_len = protected_data_len
	};
	int ret = monmod_trusted_syscall(__NR_monmod_init, 
                                         pid, 
					 (long)trusted_syscall_addr,
					 (long)monitor_enter_addr,
					 (long)&addr_ranges,
					 0,
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
	return 0; /* should never return; system call kills process */
}
