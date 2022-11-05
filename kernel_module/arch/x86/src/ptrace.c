#include "ptrace.h"
#include <asm/thread_info.h>

int monmod_ptrace_report_syscall_entry(struct pt_regs *regs)
{
	/*  We emulate the following lines from syscall_trace_enter_phase2()
	    in arch/x86/entry/common.c:

	   if ((ret || test_thread_flag(TIF_SYSCALL_TRACE)) &&
	   	tracehook_report_syscall_entry(regs))
	   		ret = -1L;
	*/
	if(test_thread_flag(TIF_SYSCALL_TRACE)) {
		return 1;
	}

	set_thread_flag(TIF_SYSCALL_TRACE);
	// NOTE: our implementation discards tracehook_report_syscall_entry 
	// return value
	tracehook_report_syscall_entry(regs);
	clear_thread_flag(TIF_SYSCALL_TRACE);

	return 0;
}

int monmod_ptrace_report_syscall_exit(struct pt_regs *regs)
{
	/* We emulate the following lines from syscall_slow_exit_work()
	   in arch/x86/entry/common.c:
	   
	   step = unlikely(
		(cached_flags & (_TIF_SINGLESTEP | _TIF_SYSCALL_EMU))
		== _TIF_SINGLESTEP);
	   if (step || cached_flags & _TIF_SYSCALL_TRACE)
		tracehook_report_syscall_exit(regs, step);
	   */
	set_thread_flag(TIF_SYSCALL_TRACE);
	tracehook_report_syscall_exit(regs, 0);
	clear_thread_flag(TIF_SYSCALL_TRACE);
	return 0;
}
