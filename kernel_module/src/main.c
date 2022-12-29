#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <trace/events/syscalls.h>
#include <linux/mman.h>

#include "build_config.h"
#include "util.h"
#include "config.h"
#include "tracepoint_helpers.h"
#include "syscall_trace_func.h"
#include "custom_syscalls.h"


// Global Variables
static struct tracepoint *tp_sys_enter = NULL;
static struct tracepoint *tp_sys_exit = NULL;


// Helpers

static int redirect_to_user_trace_func(void __user *target, 
                                       struct pt_regs *regs)
{
	void __user *old_sp = (void __user *)STACK_PTR_REG(regs);
	struct syscall_trace_func_stack stack = {};
	void __user *new_sp = old_sp - sizeof(stack) - 128;
	memcpy(&stack.regs, regs, sizeof(stack.regs));
	TRY(copy_to_user(new_sp, (void *)&stack, sizeof(stack)),
	    return 1);
	STACK_PTR_REG(regs) = (unsigned long)new_sp;
	PC_REG(regs) = (unsigned long)target;
	return 0;
}

static void set_syscall_unprotect_monitor(
		struct monmod_tracee_config *tracee_conf,
		struct pt_regs *regs)
{
	SYSCALL_NO_REG(regs) = __NR_mprotect;
	SYSCALL_ARG0_REG(regs) = (long)tracee_conf->monitor_start;
	SYSCALL_ARG1_REG(regs) = (long)tracee_conf->monitor_len;
	SYSCALL_ARG2_REG(regs) = PROT_READ | PROT_EXEC;
	SYSCALL_ARG3_REG(regs) = 0;
	SYSCALL_ARG4_REG(regs) = 0;
	SYSCALL_ARG5_REG(regs) = 0;
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> Unprotecting pages with "
	       "mprotect(%p, %lx, %x)\n", current->pid, 
	       tracee_conf->monitor_start,
	       tracee_conf->monitor_len,
	       PROT_READ | PROT_EXEC);
#endif
}

static inline bool syscall_breaks_protection(
		struct monmod_tracee_config *tracee_conf,
		struct pt_regs *regs, long id)
{
	switch(id) {
		case __NR_mmap:
		case __NR_munmap:
		case __NR_mprotect: {
			void __user *addr = (void __user *)
			                    SYSCALL_ARG0_REG(regs);
			size_t len = (size_t)SYSCALL_ARG1_REG(regs);
			void __user *monitor_start = tracee_conf->monitor_start;
			void __user *monitor_end = monitor_start
			                           + tracee_conf->monitor_len;
			if(BETWEEN(addr, monitor_start, monitor_end)
			   || BETWEEN(addr + len, monitor_start, monitor_end)) {
				return true;
			}
		}
	}
	return false;
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

static bool in_unprotect_call = false;

static void sys_enter_probe(void *__data, struct pt_regs *regs, long id)
{
	const pid_t pid = current->pid;
	struct monmod_tracee_config *tracee_conf = NULL;
	if(0 != monmod_global_config.active && is_monmod_syscall(id)) {
		return custom_syscall_enter(__data, regs, id);
	}
	if(0 != probe_prelude(__data, regs)) {
		return;
	}
	if(NULL == (tracee_conf = monmod_get_tracee_config(current->pid))) {
		printk(KERN_WARNING "monmod: <%d> cannot get config for "
		       "tracee although it is traced.\n", pid);
		return;
	}
	if(syscall_breaks_protection(tracee_conf, regs, id)) {
		printk(KERN_WARNING "monmod: <%d> system call attempted to "
		       "alter memory protection of monitor area.\n", pid);
		/* The following should cause a -ENOSYS return on both x86_64 
		and aarch64. If we use -1, aarch64 will go through the
		__sys_trace_return_skipped path (entry.S:719), which will also 
		report trace_sys_exit(). For consistency with x86_64, which does 
		not do that, we choose -2, which sould be well out of range as 
		well and return -ENOSYS on both architectures. */
		SYSCALL_NO_REG(regs) = (unsigned long)-2;
		return;
	}
	if(!monmod_syscall_is_active(id)) {
		return;
	}

	if(!tracee_conf->active) {
#if MONMOD_LOG_INFO
		printk(KERN_INFO "monmod: <%d> Entering trusted system call "
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
	printk(KERN_INFO "monmod: <%d> Forwarding untrusted system call %lu "
	                 "entry\n", 
	       pid, id);
#endif

	/* Set up the registers and stack so we will continue in the monitoring 
	   function upon kernel exit. */
	redirect_to_user_trace_func(tracee_conf->trace_func_addr, regs);

	/* Change system call arguments to actually issue an mprotect call that
	   allows execution of the otherwise protected region of monitor code.*/
	set_syscall_unprotect_monitor(tracee_conf, regs);
	in_unprotect_call = true;
	tracee_conf->active = false;
}

static void sys_exit_probe(void *__data, struct pt_regs *regs, 
                           unsigned long return_value)
{
	struct monmod_tracee_config *tracee_conf = NULL;
	if(0 != probe_prelude(__data, regs)) {
		return;
	}
	// TODO document why whe can do this after probe_prelude here
	// (it is because pid will be registered as traced by here)
	if(1 == custom_syscall_exit(__data, regs, return_value)) {
		return;
	}
	if(NULL == (tracee_conf = monmod_get_tracee_config(current->pid))) {
		printk(KERN_WARNING "monmod: <%d> cannot get config for "
		       "tracee although it is traced.\n", current->pid);
		return;
	}
	if(in_unprotect_call) {
		if(0 != SYSCALL_RET_REG(regs)) {
			printk(KERN_WARNING "monmod: <%d> mprotect failed with "
			"return value %lld.\n", current->pid, 
			(long long int)SYSCALL_RET_REG(regs));
		}
		in_unprotect_call = false;
	}
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
