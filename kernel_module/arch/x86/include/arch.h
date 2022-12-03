#ifndef X86_ARCH_H
#define X86_ARCH_H

#ifndef TEST_H
#include "linux/syscalls.h"
#endif

#define __NR_syscalls  __NR_execveat

#define SYSCALL_INSTR_SIZE 2 // syscall == 0f 05

#define PC_REG(regs) (regs->ip)
#define STACK_BASE_PTR_REG(reg) (regs->bp)
#define STACK_PTR_REG(regs) (regs->sp)
#define SYSCALL_NO_REG(regs) (regs->orig_ax)

#endif