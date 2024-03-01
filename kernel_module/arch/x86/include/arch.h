#ifndef X86_ARCH_H
#define X86_ARCH_H

#ifndef TEST_H
#include "linux/syscalls.h"
#endif

#define MIN_SYSCALL_NO __NR_read
#define MAX_SYSCALL_NO __NR_mlock2
#ifndef __NR_syscalls
#define __NR_syscalls  (MAX_SYSCALL_NO-MIN_SYSCALL_NO)
#endif

#define SYSCALL_INSTR_SIZE 2 // syscall == 0f 05

#define PC_REG(regs)            ((regs)->ip)
#define STACK_BASE_PTR_REG(reg) ((regs)->bp)
#define STACK_PTR_REG(regs)     ((regs)->sp)
#define SYSCALL_NO_REG(regs)    ((regs)->orig_ax)
#define SYSCALL_RET_REG(regs)   ((regs)->ax)

#define SYSCALL_ARG0_REG(regs)  ((regs)->di)
#define SYSCALL_ARG1_REG(regs)  ((regs)->si)
#define SYSCALL_ARG2_REG(regs)  ((regs)->dx)
#define SYSCALL_ARG3_REG(regs)  ((regs)->r10)
#define SYSCALL_ARG4_REG(regs)  ((regs)->r8)
#define SYSCALL_ARG5_REG(regs)  ((regs)->r9)
#define SYSCALL_ARG6_REG(regs)  (NULL)

#endif