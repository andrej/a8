#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <elf.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/uio.h>

#define TRY(x) { if(0 != (x)) { \
	printf("Something went wrong at " #x "\n"); \
	return 1; \
}}

// Swap this from PTRACE_SYSCALL to PTRACE_CONT when using monmod
//#define PTRACE_CONTINUE_REQ PTRACE_SYSCALL
#define PTRACE_CONTINUE_REQ PTRACE_CONT

int read_user_regs(pid_t pid, struct user_regs_struct *into)
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
	printf(" <8: %lld>", (long long)regs->regs[8]);
	// for(int i = 0; i < 31; i++) {
	// 	printf(" <%d: %lld>", i, (long long)regs->regs[i]);
	// }
	printf("\n");
}

int main(int argc, char **argv)
{
	pid_t child;
	time_t t;
	int in_syscall, status;
	struct user_regs_struct regs;
	if((child = fork()) == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		// Child
		for(;;) {
			t = time(NULL);
			printf("<%d> %lu\n", getpid(), t);
			sleep(1);
		}
		return 0;
	} else {
		printf("Parent: <%d>\n", getpid());
		for(; wait(&status) > 0 && !WIFSTOPPED(status); );
		if(!WIFSTOPPED(status)) {
			printf("Something went wrong trying to attach.\n");
			return 1;
		}
		TRY(ptrace(PTRACE_CONTINUE_REQ, child, 0, 0));
		in_syscall = 0;
		while(wait(&status) > 0) {
			in_syscall = !in_syscall;
			if(!WIFSTOPPED(status)) {
				continue;
			}
			if(in_syscall == 0) {
				printf("Entering syscall.\n");
			} else {
				printf("Exiting syscall.\n");
			}
			TRY(read_user_regs(child, &regs));
			print_regs(&regs);
			// Continue execution
			TRY(ptrace(PTRACE_CONTINUE_REQ, child, 0, 0));
			status = 0;
		}
	}
	return 0;
}