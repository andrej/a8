#ifndef ARM64_ARCH_H
#define ARM64_ARCH_H

#define SYSCALL_INSTR_SIZE 4 

#define PC_REG(regs) (regs->pc)
#define STACK_PTR_REG(regs) (regs->sp)
#define STACK_BASE_PTR_REG(reg) (regs->bp)

/* Kernel receives the system call number in w8 and uses that register value
   as the system call number on regular entry (entry.S:685).

   However, user-space passes the system call number as the first argument
   to syscall(no, ...), in w0. Glibc moves w0 to w8.

   For some reason, when tracing code is activated in the kernel, the register
   w0 is used to overwrite the system call number -- possibly to make it more
   "user-friendly" since to user-space code, it looks like w0 is the system
   call number. Hence, if we want to overwrite the system call number in the
   tracing path in kernel (entry.S:710 __sys_trace), we need to overwrite
   register w0. So that's what we do...
 */
#define SYSCALL_NO_REG(regs) (regs->regs[0])  // w8, not x8 (discard top 4 b!)

#define SYSCALL_RET_REG(regs) (regs->regs[0])

#define SYSCALL_ARG0_REG(regs) (regs->regs[0])
#define SYSCALL_ARG1_REG(regs) (regs->regs[1])
#define SYSCALL_ARG2_REG(regs) (regs->regs[2])
#define SYSCALL_ARG3_REG(regs) (regs->regs[3])
#define SYSCALL_ARG4_REG(regs) (regs->regs[4])
#define SYSCALL_ARG5_REG(regs) (regs->regs[5])
#define SYSCALL_ARG6_REG(regs) (regs->regs[6])

#endif