#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include "custom_syscalls.h"
#include "config.h"
#include "util.h"
#include "syscall_trace_func.h"

struct intercepted_syscalls_map intercepts = {};
bool have_intercept = false;

/* Exposed to user space:
   int monmod_init(pid_t pid, void *monitor_start, size_t monitor_len,
                void *trusted_syscall_addr, void *monitor_enter_addr) */
int sys_monmod_init(struct pt_regs *regs)
{
	const pid_t pid = (pid_t)SYSCALL_ARG0_REG(regs);
	/* Even though currently a process can only put itself into monitored
	   mode, we add the pid argument for possible future extensions. */
	void __user * const monitor_start = (void *)SYSCALL_ARG1_REG(regs);
	const size_t monitor_len = (size_t)SYSCALL_ARG2_REG(regs);
	void __user * const trusted_syscall_addr = (void *)SYSCALL_ARG3_REG(regs);
	void __user * const monitor_enter_addr = (void *)SYSCALL_ARG4_REG(regs);
	struct monmod_tracee_config *tracee_conf = NULL;
	void __user * const pc = (void __user *)PC_REG(regs);

	// Sanity checks first
	if(pid != current->pid || NULL == monitor_start
	   || !BETWEEN(pc, monitor_start, monitor_start+monitor_len)
	   || !BETWEEN(trusted_syscall_addr, monitor_start, 
	               monitor_start+monitor_len)
	   || !BETWEEN(monitor_enter_addr, monitor_start, 
	               monitor_start+monitor_len)) {
		printk(KERN_WARNING "monmod: <%d> Sanity check failed for "
		       "monmod_init(%d, %p, %lx, %p, %p) system call.\n",
		       current->pid, pid, monitor_start, monitor_len, 
		       trusted_syscall_addr, monitor_enter_addr);
		return -EINVAL;
	}
	tracee_conf = monmod_get_tracee_config(current->pid);
	if(NULL != tracee_conf) {
		/* There may be at most one initialize call per PID. A second
		   init call could be a malicious attempt to move the protected
		   monitor memory region addresses. */
		printk(KERN_WARNING "monmod: <%d> Attempt to reinitialize "
		       "already initialized monitor.\n", current->pid);
		return -EINVAL;
	}

	if(0 != monmod_add_tracee_config(pid)) {
		printk(KERN_WARNING "monmod: <%d> Unable to add "
		       "tracee config.\n", pid);
		return -ENOMEM;
	}
	tracee_conf = monmod_get_tracee_config(current->pid);
	if(NULL == tracee_conf) {
		printk(KERN_WARNING "monmod: <%d> Confused -- just added "
		       "tracee config, but cannot find it.\n", current->pid);
		return -EBADE;
	}
	tracee_conf->active = false; /* until first reprotect call */
	tracee_conf->monitor_start = monitor_start;
        tracee_conf->monitor_len = monitor_len;
        tracee_conf->trusted_addr = trusted_syscall_addr;
        tracee_conf->trace_func_addr = monitor_enter_addr;

	printk(KERN_INFO "monmod: <%d> Added tracing. Monitor: %p - %p. "
	       "Trusted syscall address: %p. Trace function address: %p.\n",
	       current->pid, tracee_conf->monitor_start,
	       tracee_conf->monitor_start + tracee_conf->monitor_len,
	       tracee_conf->trusted_addr, tracee_conf->trace_func_addr);

	return 0;
}

/* Exposed to user space:
   int monmod_reprotect(bool write_back_regs, 
                        struct syscall_trace_func_stack *stack);
   */
static bool is_in_reprotect_call = false;
static bool write_back_regs = false;
static void __user *ret_addr = NULL;
static struct syscall_trace_func_stack reprotect_stack = {};

int sys_monmod_reprotect(struct pt_regs *regs)
{
	struct monmod_tracee_config *tracee_conf;
	bool _write_back_regs = (bool)SYSCALL_ARG0_REG(regs);
	void __user *reprotect_stack_addr = (void __user *)
	                                    SYSCALL_ARG1_REG(regs);
	if(NULL == (tracee_conf = monmod_get_tracee_config(current->pid))) {
		printk(KERN_WARNING "monmod: <%d> cannot get config for "
		       "tracee during reprotect system call.\n", current->pid);
		return -EBADE;
	}

	write_back_regs = _write_back_regs;
	if(write_back_regs) {
		TRY(copy_from_user(&reprotect_stack, reprotect_stack_addr,
				sizeof(reprotect_stack)),
		return 1);
		ret_addr = (void __user *)PC_REG(&reprotect_stack.regs);
	} else {
		ret_addr = reprotect_stack_addr;
	}
	is_in_reprotect_call = true;

	if(BETWEEN(ret_addr, tracee_conf->monitor_start,
	           tracee_conf->monitor_start + tracee_conf->monitor_len)) {
		printk(KERN_WARNING "monmod: <%d> cannot return into monitor "
		       "after reprotect call -- that memory is going to be "
		       "inaccessible.\n", current->pid);
		return -EINVAL;
	}

	SYSCALL_NO_REG(regs) = __NR_mprotect;
	SYSCALL_ARG0_REG(regs) = (long)tracee_conf->monitor_start;
	SYSCALL_ARG1_REG(regs) = (long)tracee_conf->monitor_len;
	SYSCALL_ARG2_REG(regs) = PROT_READ;
	SYSCALL_ARG3_REG(regs) = 0;
	SYSCALL_ARG4_REG(regs) = 0;
	SYSCALL_ARG5_REG(regs) = 0;
	PC_REG(regs) = (long)ret_addr;
	tracee_conf->active = true;

#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> Reprotecting monitor with "
	       "mprotect(%p, %lx, %x).\n", current->pid,
	       (void *)SYSCALL_ARG0_REG(regs), 
	       (size_t)SYSCALL_ARG1_REG(regs), 
	       (int)SYSCALL_ARG2_REG(regs));
#endif

	return 0;
}

void sys_monmod_reprotect_exit(struct pt_regs *regs)
{
	if(!is_in_reprotect_call) {
		printk(KERN_WARNING "monmod: <%d> reprotect_exit called even "
		       "though system call enter was never observed.\n", 
		       current->pid);
		return;
	}
	is_in_reprotect_call = false;
	if(0 != SYSCALL_RET_REG(regs)) {
		printk(KERN_WARNING "monmod: <%d> mprotect failed with return "
		       "value %ld.\n", current->pid, SYSCALL_RET_REG(regs));
		return;
	}
	/* Restore the registers as given in the entry arguments. */
	if(write_back_regs) {
		memcpy(regs, &reprotect_stack.regs, sizeof(*regs));
	}

#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> Reprotected monitor, returning to "
	       "address %p with return value %ld.\n", current->pid, ret_addr,
	       SYSCALL_RET_REG(regs));
#endif
}

void custom_syscall_enter(void *__data, struct pt_regs *regs, long id)
{
	const pid_t pid = current->pid;
	long ret = -ENOSYS;
	if(intercepts.size >= MAX_N_INTERCEPTS) {
		/* This will result in an -ENOSYS return. */
		return;
	}
	switch(id) {
		case __NR_monmod_init: {
			ret = sys_monmod_init(regs);
			break;
		}
		case __NR_monmod_reprotect: {
			ret = sys_monmod_reprotect(regs);
			break;
		}
	}
	if(-1 == put_intercepted_syscall((struct intercepted_syscall)
	                                 {pid, id, ret})) {
		printk(KERN_WARNING "monmod <%d>: Unable to store intercepted "
		       "syscall return.\n", pid);
	}
	have_intercept = true;
}

int custom_syscall_exit(void *__data, struct pt_regs *regs,
                                long return_value)
{
	const pid_t pid = current->pid;
	struct intercepted_syscall *intercept = NULL;
	if(!have_intercept) {
		return 0;
	}
	intercept = get_intercepted_syscall(pid);
	if(NULL == intercept) {
		return 1;
	}
	SYSCALL_RET_REG(regs) = intercept->inject_return;
	switch(intercept->syscall_no) {
		case __NR_monmod_reprotect: {
			sys_monmod_reprotect_exit(regs);
			break;
		}
	}
	pop_intercepted_syscall(intercept);
	if(intercepts.size == 0) {
		have_intercept = false;
	}
	return 1;
}
