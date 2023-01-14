#ifndef X86_ARCH_H
#define X86_ARCH_H

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <ucontext.h>

#define ARCH_x86_64 1

#define MIN_SYSCALL_NO __NR_read
#define MAX_SYSCALL_NO __NR_mlock2
#define __NR_syscalls  (MAX_SYSCALL_NO-MIN_SYSCALL_NO)

#define SYSCALL_INSTR_SIZE 2 // syscall == 0f 05
#define N_SYSCALL_ARGS 6

#define PC_REG(regs) (regs->rip)
#define STACK_BASE_PTR_REG(reg) (regs->rbp)
#define STACK_PTR_REG(regs) (regs->rsp)
#define SYSCALL_NO_REG(regs) (regs->orig_rax)
#define SYSCALL_ARG0_REG(regs) (regs->rdi)
#define SYSCALL_ARG1_REG(regs) (regs->rsi)
#define SYSCALL_ARG2_REG(regs) (regs->rdx)
#define SYSCALL_ARG3_REG(regs) (regs->r10)
#define SYSCALL_ARG4_REG(regs) (regs->r8)
#define SYSCALL_ARG5_REG(regs) (regs->r9)
#define SYSCALL_ARGS_TO_ARRAY(regs, args) { \
	args[0] = SYSCALL_ARG0_REG(regs); \
	args[1] = SYSCALL_ARG1_REG(regs); \
	args[2] = SYSCALL_ARG2_REG(regs); \
	args[3] = SYSCALL_ARG3_REG(regs); \
	args[4] = SYSCALL_ARG4_REG(regs); \
	args[5] = SYSCALL_ARG5_REG(regs); \
}

#define UCONTEXT_PC(c) (((ucontext_t *)c)->uc_mcontext.gregs[REG_RIP])

#endif