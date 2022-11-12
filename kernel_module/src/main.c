#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <trace/events/syscalls.h>

#include "build_config.h"
#include "util.h"
#include "config.h"
#include "ptrace.h"
#include "tracepoint_helpers.h"

// Macros
#define NO_SYSCALL (__NR_syscalls+1)

// Global Variables
static struct tracepoint *tp_sys_enter = NULL;
static struct tracepoint *tp_sys_exit = NULL;
u64 last_syscall = NO_SYSCALL;

// Functions
static inline int probe_prelude(void *__data, struct pt_regs *regs, u64 id)
{

	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
	if(monmod_global_config.tracee_pid != current->pid
	   || !(current->ptrace & PT_PTRACED) 
	   || !monmod_syscall_is_active(id)) {
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
	if(0 != probe_prelude(__data, regs, id)) {
		return;
	}
	last_syscall = id;
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call %lu entry\n", 
	       monmod_global_config.tracee_pid, id);
#endif
	if(0 != monmod_ptrace_report_syscall_entry(regs)) {
		printk(KERN_WARNING " monmod: target client used "
		       "PTRACE_SYSCALL, "
		       "which is not the intended use. Use PTRACE_CONT to be "
		       "notified of syscall stops under monmod.\n");
	}
}

static void sys_exit_probe(void *__data, struct pt_regs *regs, 
                           unsigned long return_value)
{
	if(NO_SYSCALL == last_syscall) {
		return;
	}
	if(0 != probe_prelude(__data, regs, last_syscall)) {
		return;
	}
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call exit value %lu\n",
	       monmod_global_config.tracee_pid, return_value);
#endif
	if(0 != monmod_ptrace_report_syscall_exit(regs)) {
		printk(KERN_WARNING " monmod: target client used "
		       "PTRACE_SYSCALL, "
		       "which is not the intended use. Use PTRACE_CONT to be "
		       "notified of syscall stops under monmod.\n");
	}
	last_syscall = NO_SYSCALL;
}


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
