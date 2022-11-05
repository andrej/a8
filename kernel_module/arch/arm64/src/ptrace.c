#include "ptrace.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
/* In these versions, the ptrace_report_syscall signature looks like this:
   static inline int ptrace_report_syscall(unsigned long message) */
#error "monmod_ptrace_report_syscall_entry() not implemented for this kernel " \
       "version."
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
/* In these versions, the ptrace_report_syscall signature looks like this:
   static inline int ptrace_report_syscall(struct pt_regs *regs,
					unsigned long message) */
#error "monmod_ptrace_report_syscall_entry() not implemented for this kernel " \
       "version."
#else
/* In these versions, the ptrace_report_syscall signature looks like this:
   static inline int ptrace_report_syscall(struct pt_regs *regs) */


/* ************************************************************************** *
 * Internals: Kernel Release 4.4.116 arch/arm64/kernel/ptrace.c 1227-1252     *
 * ************************************************************************** */

enum ptrace_syscall_dir {
	PTRACE_SYSCALL_ENTER = 0,
	PTRACE_SYSCALL_EXIT,
};

static void tracehook_report_syscall(struct pt_regs *regs,
				     enum ptrace_syscall_dir dir)
{
	int regno;
	unsigned long saved_reg;

	/*
	 * A scratch register (ip(r12) on AArch32, x7 on AArch64) is
	 * used to denote syscall entry/exit:
	 */
	regno = (is_compat_task() ? 12 : 7);
	saved_reg = regs->regs[regno];
	regs->regs[regno] = dir;

	if (dir == PTRACE_SYSCALL_EXIT)
		tracehook_report_syscall_exit(regs, 0);
	else if (tracehook_report_syscall_entry(regs))
		regs->syscallno = ~0UL;

	regs->regs[regno] = saved_reg;
}


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_ptrace_report_syscall_entry(struct pt_regs *regs)
{

	/* Emulate the following code from syscall_trace_enter() 
	   if (test_thread_flag(TIF_SYSCALL_TRACE))
	   	tracehook_report_syscall(regs, PTRACE_SYSCALL_ENTER); */
	
	if(test_thread_flag(TIF_SYSCALL_TRACE)) {
		return 1;
	}

	set_thread_flag(TIF_SYSCALL_TRACE);
	// NOTE: our implementation discards tracehook_report_syscall_entry 
	// return value
	tracehook_report_syscall(regs, PTRACE_SYSCALL_ENTER);
	clear_thread_flag(TIF_SYSCALL_TRACE);

	return 0;
}

int monmod_ptrace_report_syscall_exit(struct pt_regs *regs)
{
	/* This is what we're working with in kernel syscall_trace_exit():

	   audit_syscall_exit(regs);

	   if (test_thread_flag(TIF_SYSCALL_TRACEPOINT))
	   	trace_sys_exit(regs, regs_return_value(regs));

	   if (test_thread_flag(TIF_SYSCALL_TRACE))
	   	tracehook_report_syscall(regs, PTRACE_SYSCALL_EXIT); */
	if (test_thread_flag(TIF_SYSCALL_TRACE)) {
		return 1;
	}
	set_thread_flag(TIF_SYSCALL_TRACE);
	tracehook_report_syscall(regs, PTRACE_SYSCALL_EXIT);
	// It is important that we clear the flag again, or the syscall exit
	// will immediately be double-reported (see above code in comment)
	clear_thread_flag(TIF_SYSCALL_TRACE);

	return 0;
}



#endif