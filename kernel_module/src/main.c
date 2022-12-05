#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <trace/events/syscalls.h>

#include "build_config.h"
#include "util.h"
#include "config.h"
#include "ptrace.h"
#include "tracepoint_helpers.h"
#include "syscall_trace_func.h"

// Macros
#define __NR_monmod_toggle (__NR_syscalls+2)

// Global Variables
static struct tracepoint *tp_sys_enter = NULL;
static struct tracepoint *tp_sys_exit = NULL;


// Helpers

static int redirect_to_user_trace_func(void __user *target, 
                                       struct pt_regs *regs)
{
	void __user *old_sp = (void __user *)STACK_PTR_REG(regs);
	void __user *ret_addr = (void __user *)PC_REG(regs);
	/* This stack looks "upside down" because copy_to_user() will write
	   contiguously from low address to high address, but the stack grows
	   from high address to low addres. In other words, the first element 
	   in this array will be at the bottom (top element of stack). */
	struct syscall_trace_func_stack stack = {};
	/* The new stack pointer puts some information past the red zone.
	   The called callback function is responsible for resetting the 
	   stack pointer and properly returning to the original code that
	   invoked the syscall. */
	void __user *new_sp = old_sp - sizeof(stack) - 128;
	stack.ret_addr = (long)ret_addr;
	stack.saved_regs = *regs;
	TRY(copy_to_user(new_sp, (void *)&stack, sizeof(stack)),
	    return 1);
	STACK_PTR_REG(regs) = (unsigned long)new_sp;
	PC_REG(regs) = (unsigned long)target;
	return 0;
}

static int sys_monmod_toggle(struct pt_regs *regs,
                             struct monmod_tracee_config *tracee_conf)
{
	const pid_t pid = current->pid;
	if(tracee_conf->trusted_addr == (void *)PC_REG(regs)) {
		long arg0 = SYSCALL_ARG0_REG(regs);
		if(0 != arg0 && 1 != arg0) {
			printk(KERN_WARNING "monmod: <%d> invalid toggle call "
			       "with argument %ld.\n", pid,
			       arg0);
			return 2;
		}
		tracee_conf->active = (bool)arg0;
#if MONMOD_LOG_INFO
		if(tracee_conf->active) {
			printk(KERN_INFO "monmod: <%d> monitoring activated.\n",
				pid);
		} else {
			printk(KERN_INFO "monmod: <%d> monitoring "
				"deactivated.\n", pid);
		}
#endif
		return 1 | (tracee_conf->active << 1);
	}
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> attempt to toggle monmod monitoring "
	       "from non authorized address %p (authorized: %p)\n",
		pid, (void *)PC_REG(regs), 
		(void *)tracee_conf->trusted_addr);
#endif
	return 2;
}


// Probes

static inline int probe_prelude(void *__data, struct pt_regs *regs)
{
	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
	if(0 == monmod_global_config.active 
	   || !monmod_is_pid_traced(current->pid)) {
		return 1;
	}
#if !MONMOD_SKIP_SANITY_CHECKS
	if(NULL != __data) {
		printk(KERN_WARNING "monmod: sanity check failed -- probe "
		       "called with non-NULL data\n");
		return 1;
	}
#endif
	return 0;
}

static void sys_enter_probe(void *__data, struct pt_regs *regs, long id)
{
	const pid_t pid = current->pid;
	struct monmod_tracee_config *tracee_conf = NULL;
	if(0 != probe_prelude(__data, regs)) {
		return;
	}
	if(__NR_monmod_toggle != id && !monmod_syscall_is_active(id)) {
		return;
	}
	if(NULL == (tracee_conf = monmod_get_tracee_config(current->pid))) {
		printk(KERN_WARNING "monmod: <%d> cannot get config for "
		       "tracee although it is traced.\n", pid);
		return;
	}
	tracee_conf->inject_return = 0;
	tracee_conf->last_syscall = id;

	if(__NR_monmod_toggle == id) {
		tracee_conf->inject_return = 
			sys_monmod_toggle(regs, tracee_conf);
		return;
	}

	if(!tracee_conf->active) {
#if MONMOD_LOG_INFO
		printk(KERN_INFO "monmod: <%d> entering trusted system call "
		       "%lu at PC %p\n", pid,
		       (unsigned long)SYSCALL_NO_REG(regs),
		       (void *)PC_REG(regs));
#endif
		/* Let code inside the trusted region issue system calls
		   regularly with no intervention from this module (otherwise
		   would lead to infinite recurison). */
		return;
	}

#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call %lu entry\n", 
	       pid, id);
#endif

	redirect_to_user_trace_func(tracee_conf->trace_func_addr, regs);
	/* The following should cause a -ENOSYS return on both x86_64 and
	   aarch64. If we use -1, aarch64 will go through the
	   __sys_trace_return_skipped path (entry.S:719), which will also report
	   trace_sys_exit(). For consistency with x86_64, which does not do
	   that, we choose -2, which sould be well out of range as well and
	   return -ENOSYS on both architectures. */
	SYSCALL_NO_REG(regs) = (unsigned long)-2;
	
}

static void sys_exit_probe(void *__data, struct pt_regs *regs, 
                           unsigned long return_value)
{
	struct monmod_tracee_config *tracee_conf = NULL;
	const pid_t pid = current->pid;
	long no = 0;
	if(0 != probe_prelude(__data, regs)) {
		return;
	}
	if(NULL == (tracee_conf = monmod_get_tracee_config(current->pid))) {
		printk(KERN_WARNING "monmod: <%d> cannot get config for "
		       "tracee although it is traced.\n", pid);
		return;
	}
	no = tracee_conf->last_syscall;
	tracee_conf->last_syscall = MONMOD_NO_SYSCALL;
	if(MONMOD_NO_SYSCALL == no) {
		return;
	}

	if(__NR_monmod_toggle == no) {
		return_value = tracee_conf->inject_return;
		SYSCALL_RET_REG(regs) = tracee_conf->inject_return;
	}

#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call %ld exit value "
	       " %lu\n", pid, no, return_value);
#endif
}


// Init

static int __init monmod_init(void)
{
	if(0 != monmod_config_init()) {
		goto abort1;
	}
	tp_sys_enter = monmod_find_kernel_tracepoint_by_name("sys_enter");
	if(NULL == tp_sys_enter) {
		printk(KERN_WARNING "could not find sys_enter tracepoint\n");
		goto abort2;
	}
	tp_sys_exit = monmod_find_kernel_tracepoint_by_name("sys_exit");
	if(NULL == tp_sys_exit) {
		printk(KERN_WARNING "could not find sys_exit tracepoint\n");
		goto abort2;
	}
	TRY(tracepoint_probe_register(tp_sys_enter, (void *)sys_enter_probe, 
	                              NULL),
	    goto abort2);
	TRY(tracepoint_probe_register(tp_sys_exit, (void *)sys_exit_probe, 
	                              NULL),
	    goto abort3);
	printk(KERN_INFO "monmod: module loaded\n");
	return 0;
abort3:
	tracepoint_probe_unregister(tp_sys_exit, (void *)sys_exit_probe, 
	                            NULL);
abort2:
	monmod_config_free();
abort1:
	return -1;
}

static void __exit monmod_exit(void)
{
	if(NULL != tp_sys_enter) {
		TRY(tracepoint_probe_unregister(tp_sys_enter, 
		                                (void *)sys_enter_probe, 
						NULL),
		printk(KERN_WARNING "monmod: unable to remove sys_enter "
					"tracepoint\n"));
	}
	if(NULL != tp_sys_exit) {
		TRY(tracepoint_probe_unregister(tp_sys_exit, 
		                                (void *)sys_exit_probe, 
						NULL),
		printk(KERN_WARNING "monmod: unable to remove sys_exit "
					"tracepoint\n"));
	}
	tracepoint_synchronize_unregister();
	monmod_config_free();
	printk(KERN_INFO "monmod: module unloaded\n");
}

module_init(monmod_init);
module_exit(monmod_exit);
MODULE_LICENSE("GPL");
