#ifndef X86_ARCH_H
#define X86_ARCH_H

#include <sys/syscall.h>

#define __NR_syscalls  __NR_execveat
#define MIN_SYSCALL_NO __NR_read
#define MAX_SYSCALL_NO __NR_mlock2

#define SYSCALL_INSTR_SIZE 2 // syscall == 0f 05

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
#define SYSCALL_ARG6_REG(regs) (NULL)

#endif