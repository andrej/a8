#ifndef ARM64_ARCH_H
#define ARM64_ARCH_H

#ifndef TEST_H
#include <linux/syscalls.h>
#else
#include <sys/syscall.h>
#endif

#define MIN_SYSCALL_NO __NR_io_setup
#define MAX_SYSCALL_NO __NR_syscalls

#define SYSCALL_INSTR_SIZE 4 

#define PC_REG(regs)            ((regs)->pc)
#define STACK_PTR_REG(regs)     ((regs)->sp)
#define STACK_BASE_PTR_REG(reg) ((regs)->bp)

/* Kernel receives the system call number in w8 and uses that register value
   as the system call number on regular entry (entry.S:685).

   On entry, .macro kernel_entry puts the register state on the stack as a
   struct pt_regs.
       (arch/arm64/kernel/entry.S:75 in kernel 4.4.0-116)
   
   On syscall entry, kernel puts the original x0 register value (first sytem 
   call argument) and the system call number (from w8) into pt_regs->orig_x0 and
   pt_regs->syscallno, respectively. Internally, the kernel uses register scno,
   which is x27, to store which system call to dispatch.
       (arch/arm64/kernel/entry.S:687 in kernel 4.4.0-116)

   In the tracing path, kernel passes in a pt_regs struct pointer to the 
   syscall_trace_enter function. (1)  It uses that function's return value as
   the (possibly new) system call number. The function returns the structs
   pt_regs->syscallno as return value. It then restores the system call
   arguments from the stack as well, that is arguments 0 - 7. (2)
       (arch/arm64/kernel/entry.S:716 (1) and :724 in kernel 4.4.0-116)
 */
#define SYSCALL_NO_REG(regs)   ((regs)->syscallno)

#define SYSCALL_RET_REG(regs)  ((regs)->regs[0])

#define SYSCALL_ARG0_REG(regs) ((regs)->regs[0])
#define SYSCALL_ARG1_REG(regs) ((regs)->regs[1])
#define SYSCALL_ARG2_REG(regs) ((regs)->regs[2])
#define SYSCALL_ARG3_REG(regs) ((regs)->regs[3])
#define SYSCALL_ARG4_REG(regs) ((regs)->regs[4])
#define SYSCALL_ARG5_REG(regs) ((regs)->regs[5])
#define SYSCALL_ARG6_REG(regs) ((regs)->regs[6])

#endif