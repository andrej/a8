#ifndef PTRACE_H
#define PTRACE_H
/**
 * The kernel does not export some of the ptrace-related functions that we need
 * to emulate reporting a syscall through ptrace. This header provides those
 * functions, and the architecture-specific files in arch/ provide their
 * implementations. The implementations are mostly just copies of kernel code
 * that is not exported.
 */

#ifndef TEST_H

#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/thread_info.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,17,15)
#include <linux/tracehook.h>
#endif

#endif

int monmod_ptrace_report_syscall_entry(struct pt_regs *regs);
int monmod_ptrace_report_syscall_exit(struct pt_regs *regs);

#endif