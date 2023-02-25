#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <trace/events/syscalls.h>
#include <linux/mman.h>
#include <linux/percpu.h>
#include <linux/hashtable.h>

#include "build_config.h"
#include "util.h"
#include "config.h"
#include "tracepoint_helpers.h"
#include "syscall_trace_func.h"
#include "tracee_info.h"
#include "custom_syscalls.h"


/* ************************************************************************** *
 * Global Variables                                                           *
 * ************************************************************************** */

static struct tracepoint *tp_sys_enter = NULL;
static struct tracepoint *tp_sys_exit = NULL;
static struct tracepoint *tp_sched_process_exit = NULL;


/* ************************************************************************** *
 * Helpers                                                                    *
 * ************************************************************************** */

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
		struct tracee *tracee,
		struct pt_regs *regs)
{
	SYSCALL_NO_REG(regs) = __NR_mprotect;
#if MONMOD_SKIP_MONITOR_PROTECTION_CALLS
	SYSCALL_NO_REG(regs) = (unsigned long)__NR_getpid;
#endif
	SYSCALL_ARG0_REG(regs) = (long)tracee->config.monitor_start;
	SYSCALL_ARG1_REG(regs) = (long)tracee->config.monitor_len;
	SYSCALL_ARG2_REG(regs) = PROT_READ | PROT_EXEC;
	SYSCALL_ARG3_REG(regs) = 0;
	SYSCALL_ARG4_REG(regs) = 0;
	SYSCALL_ARG5_REG(regs) = 0;
#if !MONMOD_SKIP_MONITOR_PROTECTION_CALLS && MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> Unprotecting pages with "
	       "mprotect(%px, %lx, %x)\n", current->pid, 
	       tracee->config.monitor_start,
	       tracee->config.monitor_len,
	       PROT_READ | PROT_EXEC);
#endif
}

/**
 * Return true if the attempted system call would remove the memory protection
 * of the monitor shared library loaded into the process. We must preven these
 * calls to keep the rest of the program from being able to modify the monitor.
 */
static inline bool syscall_breaks_protection(
		struct tracee *tracee,
		struct pt_regs *regs, long id)
{
	switch(id) {
		case __NR_mmap:
		case __NR_munmap:
		case __NR_mprotect: {
			void __user *addr = (void __user *)
			                    SYSCALL_ARG0_REG(regs);
			size_t len = (size_t)SYSCALL_ARG1_REG(regs);
			void __user *monitor_start = 
				tracee->config.monitor_start;
			void __user *monitor_end = monitor_start
			                           + tracee->config.monitor_len;
			if(BETWEEN(addr, monitor_start, monitor_end)
			   || BETWEEN(addr + len, monitor_start, monitor_end)
			   || (addr <= monitor_start 
			       && addr + len >= monitor_end) ) {
				return true;
			}
			break;
		}
		// TODO: process_vm_writev
	}
	return false;
}

/* Remove a tracee and remove all associated resources. */
void destroy_tracee(struct tracee *tracee)
{
	del_tracee_info(tracee);

}

/* ************************************************************************** * 
 * Regular Syscall Monitoring                                                 *
 * ************************************************************************** */

static void regular_syscall_enter(struct pt_regs *regs, long id,
                                  struct tracee *tracee)
{
	const pid_t pid = current->pid;
#if MONMOD_LOG_VERBOSITY >= 1
	tracee->entry_info.do_log = false;
#endif
	if(syscall_breaks_protection(tracee, regs, id)) {
		printk(KERN_WARNING "monmod: <%d> system call attempted to "
		       "alter memory protection of monitor area.\n", pid);
		/* Replace the call with a harmless getpid(). We inject an
		   -EPERM return on exit. */
		SYSCALL_NO_REG(regs) = (unsigned long)__NR_getpid;
		tracee->entry_info.do_inject_return = true;
		tracee->entry_info.inject_return = -EPERM;
		return;
	}
	if(!monmod_syscall_is_active(id)) {
		return;
	}

	if(!tracee->config.active) {
#if MONMOD_LOG_VERBOSITY >= 3
		tracee->entry_info.do_log = true;
		printk(KERN_INFO "monmod: <%d> >> Enter system call (%lu) "
		       "(unmonitored) at PC %px.\n", pid,
		       (unsigned long)SYSCALL_NO_REG(regs),
		       (void *)PC_REG(regs));
#endif
		/* Let code inside the trusted region issue system calls
		   regularly with no intervention from this module (otherwise
		   would lead to infinite recurison). */
		return;
	}

#if MONMOD_LOG_VERBOSITY >= 2
	tracee->entry_info.do_log = true;
	printk(KERN_INFO "monmod: <%d> >> Enter system call (%lu) from %px.\n", 
	       pid, id, (void __user *)PC_REG(regs));
#endif

	/* Set up the registers and stack so we will continue in the monitoring 
	   function upon kernel exit. */
	redirect_to_user_trace_func(tracee->config.trace_func_addr, regs);

	/* Change system call arguments to actually issue an mprotect call that
	   allows execution of the otherwise protected region of monitor code.*/
	set_syscall_unprotect_monitor(tracee, regs);
	tracee->config.active = false;
}

static void regular_syscall_exit(struct pt_regs *regs, 
                                 unsigned long return_value,
				 struct tracee *tracee)
{
	if(tracee->entry_info.do_inject_return) {
		SYSCALL_RET_REG(regs) = tracee->entry_info.inject_return;
	}
#if !MONMOD_SKIP_MONITOR_PROTECTION_CALLS
	if(__NR_monmod_reprotect == tracee->entry_info.syscall_no) {
		if(0 != SYSCALL_RET_REG(regs)) {
			printk(KERN_WARNING "monmod: <%d> mprotect failed with "
			"return value %lld.\n", current->pid, 
			(long long int)SYSCALL_RET_REG(regs));
		}
	}
#endif
#if MONMOD_LOG_VERBOSITY >= 1
	if(tracee->entry_info.do_log) {
		printk(KERN_INFO "monmod: <%d> << Exit  system call (%ld) "
		       "with return value %lld.\n", current->pid, 
		       tracee->entry_info.syscall_no, 
		       (long long int)SYSCALL_RET_REG(regs));
	}
#endif
}


/* ************************************************************************** *
 * Probes                                                                     *
 * ************************************************************************** */

static inline struct tracee *probe_prelude(void *__data, pid_t pid)
{
	struct tracee *tracee = NULL;
	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
	if(0 == monmod_global_config.active) {
		return NULL;
	}
	if(NULL == (tracee = get_tracee_info(pid))) {
		return NULL;
	}
#if !MONMOD_SKIP_SANITY_CHECKS
	if(NULL != __data) {
		printk(KERN_WARNING "monmod: sanity check failed -- probe "
		       "called with non-NULL data\n");
		return NULL;
	}
#endif
	return tracee;
}


static void sys_enter_probe(void *__data, struct pt_regs *regs, long id)
{
	const pid_t pid = current->pid;
	struct tracee *tracee = NULL;

	//rcu_read_lock();
	tracee = probe_prelude(__data, pid);

	/* Check whether we should monitor this system call entry.
	   monmod_init() gets special treatment, since we need to listen for it
	   on all processes, even untraced ones (where probe_prelude would 
	   return 1) -- since it activates tracing. */
	if(__NR_monmod_init == id) {
		tracee = sys_monmod_init_special_entry(tracee);
	}
	if(NULL == tracee) {
		goto exit;
	}

	/* Store system call entry information for retrieval by exit probe. */
	tracee->entry_info.syscall_no = id;
	tracee->entry_info.do_inject_return = false;
	tracee->entry_info.inject_return = -ENOSYS;
	tracee->entry_info.custom_data = NULL;

	if(is_monmod_syscall(id)) {
#if MONMOD_LOG_VERBOSITY >= 1
		printk(KERN_INFO "monmod: <%d> >> Enter system call (%ld) "
		       "(custom) from %px.\n", pid, id, 
		       (void __user *)PC_REG(regs));
#endif
		custom_syscall_enter(regs, id, tracee);
	} else {
		regular_syscall_enter(regs, id, tracee);
	}

exit:
	//rcu_read_unlock();
	return;
}

static void sys_exit_probe(void *__data, struct pt_regs *regs, 
                           unsigned long return_value)
{
	const pid_t pid = current->pid;
	struct tracee *tracee = NULL;

	//rcu_read_lock();

	// Check whether we should monitor this system call exit
	tracee = probe_prelude(__data, pid);
	if(NULL == tracee) {
		goto exit;
	}

	// Handle custom system call exit
	if(is_monmod_syscall(tracee->entry_info.syscall_no)) {
		custom_syscall_exit(regs, return_value, tracee);
#if MONMOD_LOG_VERBOSITY >= 1
		printk(KERN_INFO "monmod: <%d> << Exit  system call (%ld) "
		       "(custom) with return value %lld.\n", pid, 
		       tracee->entry_info.syscall_no, 
		       (long long int)SYSCALL_RET_REG(regs));
#endif
	} else {
		regular_syscall_exit(regs, return_value, tracee);
	}

exit:
	//rcu_read_unlock();
	return;
}

static void sched_process_exit_probe(void *__data, struct task_struct *tsk)
{
	struct tracee *tracee = NULL;

	//rcu_read_lock();
	tracee = probe_prelude(__data, tsk->pid);
	if(NULL == tracee) {
		goto exit;
	}

#if MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> Task exited -- freeing monmod-related "
	       "resources.\n", tsk->pid);

#endif
	destroy_tracee(tracee);

exit:
	//rcu_read_unlock();
	return;
}


/* ************************************************************************** *
 * Initialization                                                             *
 * ************************************************************************** */

static int __init monmod_init(void)
{
	if(0 != monmod_config_init()) {
		printk(KERN_WARNING "monmod: Unable to initialize config.\n");
		goto abort1;
	}
#define get_tp(_tp) \
	tp_ ## _tp = monmod_find_kernel_tracepoint_by_name(#_tp); \
	if(NULL == tp_ ## _tp) { \
		printk(KERN_WARNING "monmod: Could not find " #_tp \
		       " tracepoint.\n"); \
		goto abort2; \
	}
	get_tp(sys_enter);
	get_tp(sys_exit);
	get_tp(sched_process_exit);
#undef get_tp

	TRY(tracepoint_probe_register(tp_sys_enter, (void *)sys_enter_probe, 
	                              NULL),
	    goto abort3);
	TRY(tracepoint_probe_register(tp_sys_exit, (void *)sys_exit_probe, 
	                              NULL),
	    goto abort3);
	TRY(tracepoint_probe_register(tp_sched_process_exit,
	                              (void *)sched_process_exit_probe,
				      NULL),
	    goto abort4);

	printk(KERN_INFO "monmod: module loaded\n");
	return 0;

abort4:
	tracepoint_probe_unregister(tp_sys_exit, (void *)sys_exit_probe, 
	                            NULL);
abort3:
	tracepoint_probe_unregister(tp_sys_enter, (void *)sys_enter_probe, 
	                            NULL);
abort2:
	monmod_config_free();
abort1:
	return -1;
}

static void __exit monmod_exit(void)
{
#define free_tp(_tp) \
	if(NULL != tp_ ## _tp) { \
		TRY(tracepoint_probe_unregister(tp_ ## _tp,  \
		                                (void *)_tp ## _probe, \
						NULL), \
		printk(KERN_WARNING "monmod: unable to remove " #_tp \
					"tracepoint\n")); \
	}

	free_tp(sys_enter);
	free_tp(sys_exit);
	free_tp(sched_process_exit);

	tracepoint_synchronize_unregister();
	free_tracee_infos(); // also frees tracee configs
	monmod_config_free();
	printk(KERN_INFO "monmod: module unloaded\n");
}

module_init(monmod_init);
module_exit(monmod_exit);
MODULE_LICENSE("GPL");
