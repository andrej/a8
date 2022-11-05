#include <stdio.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include "../trace.h"
#include "../util.h"

int read_regs(pid_t pid, struct user_regs_struct *into)
{
	struct iovec dest = {
		(void *)into,
		sizeof(struct user_regs_struct)
	};
	TRY(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &dest));
	if(dest.iov_len != sizeof(struct user_regs_struct)) {
		printf("Only read %lu bytes, expected %lu.\n", 
		        dest.iov_len, sizeof(struct user_regs_struct));
		return 1;
	}
	return 0;
}

void print_regs(struct user_regs_struct *regs)
{
	printf("<pc: %p>", (void *)regs->pc);
	printf(" <syscall no: %lld>", (long long)regs->regs[8]);
	// for(int i = 0; i < 31; i++) {
	// 	printf(" <%d: %lld>", i, (long long)regs->regs[i]);
	// }
	printf("\n");
}
