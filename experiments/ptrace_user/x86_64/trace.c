#include <stdio.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include "../trace.h"
#include "../util.h"

int read_regs(pid_t pid, struct user_regs_struct *into)
{
	TRY(ptrace(PTRACE_GETREGS, pid, 0, into));
	return 0;
}

void print_regs(struct user_regs_struct *regs)
{
	printf("<pc: %p>", (void *)regs->rip);
	printf(" <syscall no: %lld>", (long long)regs->orig_rax);
	printf("\n");
}