#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <trace/events/syscalls.h>

#include "util.h"
#include "config.h"
#include "tracepoint_helpers.h"

// Global Variables
static struct tracepoint *tp_sys_enter = NULL;


// Functions
static void enter_probe(void *__data, struct pt_regs *regs, long id)
{
	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
	if(monmod_global_config.tracee_pid != current->pid
	   || !(current->ptrace & PT_PTRACED) 
	   || !monmod_syscall_is_active(id)) {
		return;
	}
	printk(KERN_INFO " monmod: <%d> system call %lu\n", 
	       monmod_global_config.tracee_pid, id);
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
	TRY(tracepoint_probe_register(tp_sys_enter, (void *)enter_probe, NULL),
	    goto abort2);
	printk(KERN_INFO "monmod loaded");
	return 0;
abort2:
	monmod_config_free();
abort1:
	return -1;
}

static void __exit monmod_exit(void)
{
	tracepoint_probe_unregister(tp_sys_enter, (void *)enter_probe, NULL);
	tracepoint_synchronize_unregister();
	monmod_config_free();
	printk(KERN_INFO "monmod unloaded\n");
}

module_init(monmod_init);
module_exit(monmod_exit);
MODULE_LICENSE("GPL");
