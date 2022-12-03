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
#define NO_SYSCALL (__NR_syscalls+1)

// Global Variables
static struct tracepoint *tp_sys_enter = NULL;
static struct tracepoint *tp_sys_exit = NULL;
u64 last_syscall = NO_SYSCALL;
bool last_was_trusted = false;


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


// Probes

static inline int probe_prelude(void *__data, struct pt_regs *regs, u64 id)
{

	// Exit as early as possible to not slow down other processes system
	// calls. Keep in mind that any code here will be run for all system
	// calls.
	if(0 == monmod_global_config.active
	   || monmod_global_config.tracee_pid != current->pid
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
	
	printk("monmod: <%d> syscall call site %p, trusted area %p + 32\n",
		monmod_global_config.tracee_pid,
	       (void *)PC_REG(regs),
	       monmod_global_config.trusted_addr);

	if(monmod_global_config.trusted_addr <= (void *)PC_REG(regs)
	   && (void *)PC_REG(regs) <= monmod_global_config.trusted_addr + PAGE_SIZE) {
	   /* FIXME FIXME FIXME -- Proeprly define trusted region start and
	      end addresses. */
	   	last_was_trusted = true;
#if MONMOD_LOG_INFO
		printk(KERN_INFO "monmod: trusted syscall at PC %p\n",
		       (void *)PC_REG(regs));
#endif
		/* Let code inside the trusted region issue system calls
		   regularly with no intervention from this module (otherwise
		   would lead to infinite recurison). */
		return;
	}
	last_was_trusted = false;

	last_syscall = id;
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call %lu entry\n", 
	       monmod_global_config.tracee_pid, id);
#endif

	redirect_to_user_trace_func(monmod_global_config.trusted_addr, regs);
	SYSCALL_NO_REG(regs) = (unsigned long)-1;

	// Put stuff on user stack
	
	//if(0 != monmod_ptrace_report_syscall_entry(regs)) {
	//	printk(KERN_WARNING " monmod: target client used "
	//	       "PTRACE_SYSCALL, "
	//	       "which is not the intended use. Use PTRACE_CONT to be "
	//	       "notified of syscall stops under monmod.\n");
	//}
}

static void sys_exit_probe(void *__data, struct pt_regs *regs, 
                           unsigned long return_value)
{
	if(NO_SYSCALL == last_syscall || last_was_trusted) {
		return;
	}
	if(0 != probe_prelude(__data, regs, last_syscall)) {
		return;
	}
#if MONMOD_LOG_INFO
	printk(KERN_INFO "monmod: <%d> forwarding system call exit value %lu\n",
	       monmod_global_config.tracee_pid, return_value);
#endif
	//if(0 != monmod_ptrace_report_syscall_exit(regs)) {
	//	printk(KERN_WARNING " monmod: target client used "
	//	       "PTRACE_SYSCALL, "
	//	       "which is not the intended use. Use PTRACE_CONT to be "
	//	       "notified of syscall stops under monmod.\n");
	//}
	last_syscall = NO_SYSCALL;
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
