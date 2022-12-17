#ifndef ARM64_ARCH_H
#define ARM64_ARCH_H

#define SYSCALL_INSTR_SIZE 4 
#define N_SYSCALL_ARGS 7 

#define PC_REG(regs) (regs->pc)
#define STACK_PTR_REG(regs) (regs->sp)
#define STACK_BASE_PTR_REG(reg) (regs->bp)
#define SYSCALL_NO_REG(regs) (regs->regs[8])  // w8, not x8 (discard top 4 b!)
#define SYSCALL_ARG0_REG(regs) (regs->regs[0])
#define SYSCALL_ARG1_REG(regs) (regs->regs[1])
#define SYSCALL_ARG2_REG(regs) (regs->regs[2])
#define SYSCALL_ARG3_REG(regs) (regs->regs[3])
#define SYSCALL_ARG4_REG(regs) (regs->regs[4])
#define SYSCALL_ARG5_REG(regs) (regs->regs[5])
#define SYSCALL_ARG6_REG(regs) (regs->regs[6])
#define SYSCALL_ARGS_TO_ARRAY(regs, args) { \
	args[0] = SYSCALL_ARG0_REG(regs); \
	args[1] = SYSCALL_ARG1_REG(regs); \
	args[2] = SYSCALL_ARG2_REG(regs); \
	args[3] = SYSCALL_ARG3_REG(regs); \
	args[4] = SYSCALL_ARG4_REG(regs); \
	args[5] = SYSCALL_ARG5_REG(regs); \
	args[6] = SYSCALL_ARG6_REG(regs); \
}

#endif