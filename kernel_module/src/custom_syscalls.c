#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include "custom_syscalls.h"
#include "config.h"
#include "util.h"
#include "tracee_info.h"
#include "syscall_trace_func.h"


/* ************************************************************************** *
 * Custom System Calls                                                        *
 * ************************************************************************** */

/* Exposed to user space:
   int monmod_init(pid_t pid, void *monitor_start, size_t monitor_len,
                void *trusted_syscall_addr, void *monitor_enter_addr) */
int sys_monmod_init(struct pt_regs *regs, struct tracee *tracee)
{
	const pid_t pid = (pid_t)SYSCALL_ARG0_REG(regs);
	/* Even though currently a process can only put itself into monitored
	   mode, we add the pid argument for possible future extensions. */
	void __user * const monitor_start = \
		(void __user *)SYSCALL_ARG1_REG(regs);
	const size_t monitor_len = (size_t)SYSCALL_ARG2_REG(regs);
	void __user * const trusted_syscall_addr = \
		(void __user *)SYSCALL_ARG3_REG(regs);
	void __user * const monitor_enter_addr = \
		(void __user *)SYSCALL_ARG4_REG(regs);

	// Sanity checks first
	if(pid != current->pid || NULL == monitor_start
	   || !BETWEEN(trusted_syscall_addr, monitor_start, 
	               monitor_start+monitor_len)
	   || !BETWEEN(monitor_enter_addr, monitor_start, 
	               monitor_start+monitor_len)) {
		printk(KERN_WARNING "monmod: <%d> Sanity check failed for "
		       "monmod_init(%d, %px, %lx, %px, %px) system call.\n",
		       current->pid, pid, monitor_start, monitor_len, 
		       trusted_syscall_addr, monitor_enter_addr);
		/* We do not check for a PC between the monitor_start and 
		   monitor end addresses; our checkpointing code initializes
		   monmod from outside of this range ("unprotected" section). */
		return -EINVAL;
	}

	tracee->config.monitor_start = monitor_start;
	tracee->config.monitor_len = monitor_len;
	tracee->config.trusted_addr = trusted_syscall_addr;
	tracee->config.trace_func_addr = monitor_enter_addr;

	tracee->config.active = false; /* until first reprotect call */

#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_FLAG_PROTECTED
	tracee->protection_state = TRACEE_UNINITIALIZED;
#endif

	printk(KERN_INFO "monmod: <%d> Added tracing. Monitor: %px - %px. "
	       "Trusted syscall address: %px. Trace function address: %px.\n",
	       current->pid, tracee->config.monitor_start,
	       tracee->config.monitor_start + tracee->config.monitor_len,
	       tracee->config.trusted_addr, tracee->config.trace_func_addr);

	return 0;
}

struct tracee *sys_monmod_init_special_entry(struct tracee *tracee)
{
	const pid_t pid = current->pid;
	BUG_ON(!rcu_read_lock_held());
	if(NULL != tracee) {
		/* There may be at most one initialize call per PID. A second
		init call could be a malicious attempt to move the protected
		monitor memory region addresses. */
		printk(KERN_WARNING "monmod: <%d> Attempt to reinitialize "
		"already initialized monitor.\n", pid);
		return NULL;
	}
	tracee = add_tracee_info(pid);
	if(NULL == tracee) {
		printk(KERN_WARNING "monmod: <%d> Unable to add tracee "
			"info upon initialization.\n", pid);
		return NULL;
	}
	return tracee;
}

/* Exposed to user space:
   int monmod_reprotect(bool write_back_regs, 
                        struct syscall_trace_func_stack *stack);
   */
struct reprotect_info {
	bool write_back_regs;
	void __user *ret_addr;
	struct syscall_trace_func_stack reprotect_stack;
};

int sys_monmod_reprotect(struct pt_regs *regs, struct tracee *tracee)
{
	struct reprotect_info *info = NULL;
	bool write_back_regs = (bool)SYSCALL_ARG0_REG(regs);
	void __user *reprotect_stack_addr = (void __user *)
	                                    SYSCALL_ARG1_REG(regs);
	
	/* Set up data structure for information to pass to exit handler. */
	tracee->entry_info.custom_data = NULL;
	info = kmalloc(sizeof(struct reprotect_info), GFP_KERNEL);
	if(NULL == info) {
		printk(KERN_WARNING "monmod: <%d> Unable to allocate memory "
		       "internal handling of monmod_reprotect call.\n",
		       current->pid);
		return -EBADE;
	}
	tracee->entry_info.custom_data = info;

	info->write_back_regs = write_back_regs;
	if(info->write_back_regs) {
		info->reprotect_stack = (struct syscall_trace_func_stack){};
		TRY(copy_from_user(&info->reprotect_stack, 
		                   reprotect_stack_addr,
				   sizeof(info->reprotect_stack)),
		     goto abort1);
		info->ret_addr = (void __user *)
		                 PC_REG(&info->reprotect_stack.regs);
	} else {
		info->ret_addr = reprotect_stack_addr;
	}

	if(BETWEEN(info->ret_addr, tracee->config.monitor_start,
	           tracee->config.monitor_start + tracee->config.monitor_len)) {
		printk(KERN_WARNING "monmod: <%d> cannot return into monitor "
		       "after reprotect call -- that memory is going to be "
		       "inaccessible.\n", current->pid);
		goto abort1;
	}

	SYSCALL_NO_REG(regs) = __NR_getpid;
#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_MPROTECTED
	SYSCALL_NO_REG(regs) = __NR_mprotect;
	SYSCALL_ARG0_REG(regs) = (long)tracee->config.monitor_start;
	SYSCALL_ARG1_REG(regs) = (long)tracee->config.monitor_len;
	SYSCALL_ARG2_REG(regs) = PROT_READ;
	SYSCALL_ARG3_REG(regs) = 0;
	SYSCALL_ARG4_REG(regs) = 0;
	SYSCALL_ARG5_REG(regs) = 0;
#endif
	PC_REG(regs) = (long)info->ret_addr;

	tracee->config.active = true;

#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_FLAG_PROTECTED
	tracee->protection_state = TRACEE_NOT_IN_MONITOR;
#endif

#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_MPROTECTED \
    && MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> Reprotecting monitor with "
	       "mprotect(%px, %lx, %x).\n", current->pid,
	       (void *)SYSCALL_ARG0_REG(regs), 
	       (size_t)SYSCALL_ARG1_REG(regs), 
	       (int)SYSCALL_ARG2_REG(regs));
#endif

	return 0;

abort1:
	return -EINVAL;
}

void sys_monmod_reprotect_exit(struct pt_regs *regs, struct tracee *tracee)
{
	struct reprotect_info info = {};
	unsigned long mprotect_return_value = 0;

	if(NULL == tracee->entry_info.custom_data) {
		printk(KERN_WARNING "monmod: <%d> reprotect_exit called even "
		       "though system call enter was never observed.\n", 
		       current->pid);
		return;
	} else {
		// Copy onto the stack and free before we forget.
		info = *(struct reprotect_info *)tracee->entry_info.custom_data;
		kfree(tracee->entry_info.custom_data);
		tracee->entry_info.custom_data = NULL;
	}

	mprotect_return_value = (unsigned long)SYSCALL_RET_REG(regs);
#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_MPROTECTED
	if(0 != mprotect_return_value) {
		printk(KERN_WARNING "monmod: <%d> mprotect failed with return "
		       "value %ld.\n", current->pid, mprotect_return_value);
		return;
	}
#endif
	/* Restore the registers as given in the entry arguments. */
	if(info.write_back_regs) {
		/* The redirected program counter was already written on system 
		   call entry.
		   This also overwrites the system call return register. */
		memcpy(regs, &info.reprotect_stack.regs, sizeof(*regs));
		tracee->entry_info.do_inject_return = false;
	}

#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_MPROTECTED \
    && MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> mprotect returned with %ld, returning "
	       "to address %px with return value %lld.\n", current->pid, 
	       mprotect_return_value, info.ret_addr, 
	       (long long int)SYSCALL_RET_REG(regs));
#endif

}

/* Exposed to user space:
      monmod_destroy(int pid)
   */
int sys_monmod_destroy(struct pt_regs *regs, struct tracee *tracee)
{
	const pid_t pid = (pid_t)SYSCALL_ARG0_REG(regs);
	if(pid != current->pid) {
		printk(KERN_WARNING "monmod: <%d> Sanity check for "
		       "sys_monmod_destroy failed (pid %d != current %d).",
		       current->pid, pid, current->pid);
		return -EINVAL;
	}
#if MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> Unregistering.\n", pid);
#endif
	/* After unregistering, we have to kill the process; otherwise it could
	   execute unsupervised system calls. 
	   Issuing an exit_group call should kill the tracee and invoke the
	   sched_exit probe (in main.c) that does tracee cleanup. */
	SYSCALL_NO_REG(regs) = __NR_exit_group;
	SYSCALL_ARG0_REG(regs) = 0;
	return 0;
}


/* ************************************************************************** *
 * Custom System Call Interception                                            *
 * ************************************************************************** */

void custom_syscall_enter(struct pt_regs *regs, long id, struct tracee *tracee)
{
	long ret = -ENOSYS;
	switch(id) {
		case __NR_monmod_init: {
			ret = sys_monmod_init(regs, tracee);
			break;
		}
		case __NR_monmod_reprotect: {
			ret = sys_monmod_reprotect(regs, tracee);
			break;
		}
		case __NR_monmod_destroy: {
			ret = sys_monmod_destroy(regs, tracee);
			break;
		}
		default: {
			/* Not one of our known custom system calls. 
			   This should never happen, since is_monmod_syscall()
			   is queried before this function is called. */
			return;
		}
	}
	/* Execute a harmless and fast getpid instead of the unknown (to the
	   kernel) system call. Its return value will be overwriten. */
	if(id == SYSCALL_NO_REG(regs)) {
		SYSCALL_NO_REG(regs) = __NR_getpid;
	}
	tracee->entry_info.do_inject_return = true;
	tracee->entry_info.inject_return = ret;
}

void custom_syscall_exit(struct pt_regs *regs, long return_value,
                         struct tracee *tracee)
{
	switch(tracee->entry_info.syscall_no) {
		case __NR_monmod_reprotect: {
			sys_monmod_reprotect_exit(regs, tracee);
			break;
		}
	}
	SYSCALL_NO_REG(regs) = tracee->entry_info.syscall_no;
	if(tracee->entry_info.do_inject_return) {
		SYSCALL_RET_REG(regs) = tracee->entry_info.inject_return;
	}
}
