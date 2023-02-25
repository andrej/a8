#ifndef ARM64_ARCH_H
#define ARM64_ARCH_H

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <ucontext.h>

#define ARCH_aarch64 1

#define MIN_SYSCALL_NO __NR_io_setup
#define MAX_SYSCALL_NO __NR_syscalls

#define SYSCALL_INSTR_SIZE 4 
#define N_SYSCALL_ARGS 6

#define PC_REG(r)            ((r)->pc)
#define STACK_PTR_REG(r)     ((r)->sp)
#define STACK_BASE_PTR_REG(r) ((r)->bp)

#define SYSCALL_NO_REG(r)   ((r)->regs[8])  // w8, not x8 (discard top 4 b!)

#define SYSCALL_RET_REG(r)  ((r)->regs[0])

#define SYSCALL_ARG0_REG(r) ((r)->regs[0])
#define SYSCALL_ARG1_REG(r) ((r)->regs[1])
#define SYSCALL_ARG2_REG(r) ((r)->regs[2])
#define SYSCALL_ARG3_REG(r) ((r)->regs[3])
#define SYSCALL_ARG4_REG(r) ((r)->regs[4])
#define SYSCALL_ARG5_REG(r) ((r)->regs[5])
#define SYSCALL_ARG6_REG(r) ((r)->regs[6])

#define SYSCALL_ARGS_TO_ARRAY(regs, args) { \
	args[0] = SYSCALL_ARG0_REG(regs); \
	args[1] = SYSCALL_ARG1_REG(regs); \
	args[2] = SYSCALL_ARG2_REG(regs); \
	args[3] = SYSCALL_ARG3_REG(regs); \
	args[4] = SYSCALL_ARG4_REG(regs); \
	args[5] = SYSCALL_ARG5_REG(regs); \
	args[6] = SYSCALL_ARG6_REG(regs); \
}

#define UCONTEXT_PC(c) (((ucontext_t *)c)->uc_mcontext.pc)

#endif