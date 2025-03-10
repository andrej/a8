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
#if MONMOD_LOG_VERBOSITY >= 2
static struct tracepoint *tp_signal_deliver = NULL;
static struct tracepoint *tp_signal_generate = NULL;
#endif


/* ************************************************************************** *
 * Helpers                                                                    *
 * ************************************************************************** */

static int redirect_to_user_trace_func(void __user *target, 
                                       struct pt_regs *regs)
{
	void __user *old_sp = (void __user *)STACK_PTR_REG(regs);
	struct syscall_trace_func_stack stack = {};
	void __user *new_sp = old_sp - sizeof(stack) - 128;
	if((long long)new_sp % 16 != 0) {
		// The x86_64 ABI requires a 16-byte alignment of the stack
		// see https://stackoverflow.com/questions/51070716/glibc-scanf-segmentation-faults-when-called-from-a-function-that-doesnt-align-r
		new_sp -= 8;
	}
	memcpy(&stack.regs, regs, sizeof(stack.regs));
	TRY(copy_to_user(new_sp, (void *)&stack, sizeof(stack)),
	    return 1);
	STACK_PTR_REG(regs) = (unsigned long)new_sp;
	PC_REG(regs) = (unsigned long)target;
	return 0;
}

/**
 * Executed upon system call entry upon entry into the monitor. Allows monitor
 * code to run.
 * 
 * The monitor must exit through a custom system call (monmod_reprotect), which
 * ensures that upon the return to the rest of the program, the monitor is
 * reprotected.
 */
static inline void 
unprotect_monitor_enter(struct tracee *tracee, struct pt_regs *regs)
{
	tracee->config.active = false;

	SYSCALL_NO_REG(regs) = (unsigned long)__NR_getpid;

#if MONMOD_MONITOR_PROTECTION & MONMOD_MONITOR_FLAG_PROTECTED
	tracee->protection_state = TRACEE_IN_MONITOR;
#elif MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_MPROTECTED
	SYSCALL_NO_REG(regs) = __NR_mprotect;
	SYSCALL_ARG0_REG(regs) = (long)tracee->addrs.code_start;
	SYSCALL_ARG1_REG(regs) = (long)tracee->addrs.code_len;
	SYSCALL_ARG2_REG(regs) = PROT_READ | PROT_EXEC;
	SYSCALL_ARG3_REG(regs) = 0;
	SYSCALL_ARG4_REG(regs) = 0;
	SYSCALL_ARG5_REG(regs) = 0;
#if MONMOD_LOG_VERBOSITY >= 1
	printk(KERN_INFO "monmod: <%d> Unprotecting pages with "
	       "mprotect(%px, %lx, %x)\n", current->pid, 
	       tracee->addrs.code_start,
	       tracee->addrs.code_len,
	       PROT_READ | PROT_EXEC);
#endif
#endif
}

/**
 * Return true if the attempted system call would remove the memory protection
 * of the monitor shared library loaded into the process. We must prevent these
 * calls to keep the rest of the program from being able to modify the monitor.
 * 
 * Also return true if the attempted system call indicates an invalid jump
 * into the monitor memory area under the FLAG_PROTECTED protection scheme.
 */
static inline bool syscall_breaks_protection(
		const struct tracee * const tracee, 
		const struct pt_regs * const regs, long id)
{
	const void __user * const monitor_start = tracee->addrs.overall_start;
	const void __user * const monitor_end = monitor_start 
	                                        + tracee->addrs.overall_len;

#if MONMOD_MONITOR_PROTECTION == MONMOD_MONITOR_FLAG_PROTECTED
	if(tracee->protection_state == TRACEE_NOT_IN_MONITOR
	   && BETWEEN((void __user *)PC_REG(regs), monitor_start, monitor_end)) {
		return true;
	}
#endif

	switch(id) {
		case __NR_mmap:
		case __NR_munmap:
		case __NR_mprotect: {
			const void __user * const addr = 
				(const void __user *)SYSCALL_ARG0_REG(regs);
			const size_t len = (size_t)SYSCALL_ARG1_REG(regs);
			if(BETWEEN(addr, monitor_start, monitor_end)
			   || BETWEEN(addr + len, monitor_start, monitor_end)
			   || (addr <= monitor_start 
			       && addr + len >= monitor_end) ) {
				return true;
			}
			return false;
		}
		default:
			return false;
	}
}

/* Remove a tracee and remove all associated resources. */
void destroy_tracee(struct tracee *tracee)
{
	del_tracee_info(tracee);
}

/* ************************************************************************** * 
 * Regular Syscall Monitoring                                                 *
 * ************************************************************************** */

static void syscall_entry_abort(struct pt_regs *regs, struct tracee *tracee)
{
	SYSCALL_NO_REG(regs) = (unsigned long)__NR_exit_group;
	SYSCALL_ARG0_REG(regs) = -EPERM;
	tracee->entry_info.do_inject_return = true;
	tracee->entry_info.inject_return = -EPERM;
}

static void regular_syscall_enter(struct pt_regs *regs, long id,
                                  struct tracee *tracee)
{
#if MONMOD_MONITOR_PROTECTION & (MONMOD_MONITOR_HASH_PROTECTED \
                                 | MONMOD_MONITOR_COMPARE_PROTECTED)
	int s = 0;
#endif
#if MONMOD_MONITOR_PROTECTION & MONMOD_MONITOR_HASH_PROTECTED
	u64 hash = 0;
#endif
	const pid_t pid = current->pid;
#if MONMOD_LOG_VERBOSITY >= 1
	tracee->entry_info.do_log = false;
#endif

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

	if(syscall_breaks_protection(tracee, regs, id)) {
		printk(KERN_WARNING "monmod: <%d> system call attempted to "
		       "alter memory protection of monitor area.\n", pid);
		syscall_entry_abort(regs, tracee);
		return;
	}

	if(!monmod_syscall_is_active(id)) {
		return;
	}

#if MONMOD_LOG_VERBOSITY >= 2
	tracee->entry_info.do_log = true;
	printk(KERN_INFO "monmod: <%d> >> Enter system call (%lu) from %px.\n", 
	       pid, id, (void __user *)PC_REG(regs));
#endif

	/* Check whether monitor code was altered between system calls.
	   If so, abort since monitor integrity is compromised. */
#if MONMOD_MONITOR_PROTECTION & MONMOD_MONITOR_HASH_PROTECTED
	hash = hash_user_region(tracee->addrs.protected_data_start,
	                        tracee->addrs.protected_data_len);
	s = (tracee->monitor_hash == hash ? 0 : 1);
#endif
#if MONMOD_MONITOR_PROTECTION & MONMOD_MONITOR_COMPARE_PROTECTED
	s = compare_user_region(tracee->addrs.protected_data_start,
	                        tracee->monitor_code_copy,
				tracee->addrs.protected_data_len);
#endif
#if MONMOD_MONITOR_PROTECTION & (MONMOD_MONITOR_HASH_PROTECTED \
                                 | MONMOD_MONITOR_COMPARE_PROTECTED)
	if(0 != s) {
		printk(KERN_WARNING "monmod: <%d> Monitor code was altered.\n",
		       pid);
		syscall_entry_abort(regs, tracee);
		return;
	}
#endif

	/* Set up the registers and stack so we will continue in the monitoring 
	   function upon kernel exit. */
	redirect_to_user_trace_func(tracee->trace_func_addr, regs);

	/* Change system call arguments to actually issue an mprotect call that
	   allows execution of the otherwise protected region of monitor code.*/
	unprotect_monitor_enter(tracee, regs);
}

static void regular_syscall_exit(struct pt_regs *regs, 
                                 unsigned long return_value,
				 struct tracee *tracee)
{
	if(tracee->entry_info.do_inject_return) {
		SYSCALL_RET_REG(regs) = tracee->entry_info.inject_return;
	}
#if MONMOD_LOG_VERBOSITY >= 1
	if(tracee->entry_info.do_log) {
		printk(KERN_INFO "monmod: <%d> << Exit  system call (%ld) "
		       "with return value %lld.\n", current->pid, 
		       tracee->entry_info.syscall_no, 
		       (long long int)return_value);
	}
#endif
}


/* ************************************************************************** *
 * Probes                                                                     *
 * ************************************************************************** */

static inline struct tracee *probe_prelude(const void * const __data, 
                                           const pid_t pid)
{
	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
#if !MONMOD_SKIP_SANITY_CHECKS
	if(NULL != __data) {
		printk(KERN_WARNING "monmod: sanity check failed -- probe "
		       "called with non-NULL data\n");
		return NULL;
	}
#endif
	return get_tracee_info(pid);
}


static void sys_enter_probe(void *__data, struct pt_regs *regs, long id)
{
	const pid_t pid = current->pid;
	struct tracee *tracee;

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

	if(!is_monmod_syscall(id)) {
		regular_syscall_enter(regs, id, tracee);
	} else {
#if MONMOD_LOG_VERBOSITY >= 1
		printk(KERN_INFO "monmod: <%d> >> Enter system call (%ld) "
		       "(custom) from %px.\n", pid, id, 
		       (void __user *)PC_REG(regs));
#endif
		custom_syscall_enter(regs, id, tracee);
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

#if MONMOD_LOG_VERBOSITY >= 2
static void signal_deliver_probe(void *__data, int sig, struct siginfo *info, 
                                 struct k_sigaction *ka)
{
	struct tracee *tracee = NULL;
	tracee = probe_prelude(__data, current->pid);
	if(NULL == tracee || NULL == info) {
		return;
	}

	printk(KERN_INFO "monmod: <%d> Receiving signal %d.\n",
	       current->pid, sig);
	return;
}

static void signal_generate_probe(void *__data, int sig, struct siginfo *info, 
                                 struct task_struct *task, int group,
				 int result)
{
	struct tracee *tracee = NULL;
	if(NULL == task) {
		return;
	}

	tracee = probe_prelude(__data, task->pid);
	if(NULL == tracee || NULL == info) {
		return;
	}

	printk(KERN_INFO "monmod: <%d> Signal %d, generated by PID %d.\n",
	       task->pid, sig, current->pid);
	return;
}
#endif


/* ************************************************************************** *
 * Initialization                                                             *
 * ************************************************************************** */

static int register_tracepoints(void)
{
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
#if MONMOD_LOG_VERBOSITY >= 2
	get_tp(signal_deliver);
	get_tp(signal_generate);
#endif
#undef get_tp

	TRY(tracepoint_probe_register(tp_sys_enter, (void *)sys_enter_probe, 
	                              NULL),
	    goto abort1);
	TRY(tracepoint_probe_register(tp_sys_exit, (void *)sys_exit_probe, 
	                              NULL),
	    goto abort2);
	TRY(tracepoint_probe_register(tp_sched_process_exit,
	                              (void *)sched_process_exit_probe,
				      NULL),
	    goto abort3);
#if MONMOD_LOG_VERBOSITY >= 2
	TRY(tracepoint_probe_register(tp_signal_deliver,
	                              (void *)signal_deliver_probe,
				      NULL),
	    goto abort4);
	TRY(tracepoint_probe_register(tp_signal_generate,
	                              (void *)signal_generate_probe,
				      NULL),
	    goto abort5);
#endif

	return 0;

#if MONMOD_LOG_VERBOSITY >= 2
abort5:
	tracepoint_probe_unregister(tp_signal_deliver, 
	                            (void *)signal_deliver_probe, 
	                            NULL);
abort4:
	tracepoint_probe_unregister(tp_sched_process_exit, 
	                            (void *)sched_process_exit_probe, 
	                            NULL);
#endif
abort3:
	tracepoint_probe_unregister(tp_sys_exit, (void *)sys_exit_probe, 
	                            NULL);
abort2:
	tracepoint_probe_unregister(tp_sys_enter, (void *)sys_enter_probe, 
	                            NULL);
abort1:
	return 1;
}

static void unregister_tracepoints(void)
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
#if MONMOD_LOG_VERBOSITY >= 2
	free_tp(signal_deliver);
	free_tp(signal_generate);
#endif

	tracepoint_synchronize_unregister();
}

static int __init monmod_init(void)
{
	if(0 != monmod_config_init()) {
		printk(KERN_WARNING "monmod: Unable to initialize config.\n");
		goto abort1;
	}
	if(0 != register_tracepoints()) {
		goto abort2;
	}

	printk(KERN_INFO "monmod: module loaded\n");
	return 0;

abort2:
	monmod_config_free();
abort1:
	return -1;
}

static void __exit monmod_exit(void)
{
	unregister_tracepoints();
	free_tracee_infos(); // also frees tracee configs
	monmod_config_free();
	printk(KERN_INFO "monmod: module unloaded\n");
}

module_init(monmod_init);
module_exit(monmod_exit);
MODULE_LICENSE("GPL");
