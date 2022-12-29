#ifndef CUSTOM_SYSCALLS_H
#define CUSTOM_SYSCALLS_H

#include "arch.h"
#include "map.h"

#define __NR_monmod_init        (MAX_SYSCALL_NO+3)
#define __NR_monmod_reprotect   (MAX_SYSCALL_NO+4)
// TODO: Put these + function signatures into a common kernel/userspace header

#define MAX_N_INTERCEPTS 8

struct intercepted_syscall {
	pid_t pid;
	long syscall_no;
	long inject_return;
};

struct intercepted_syscalls_map map_struct(pid_t, struct intercepted_syscall,
                                           MAX_N_INTERCEPTS);
extern struct intercepted_syscalls_map intercepts;

static inline int put_intercepted_syscall(struct intercepted_syscall ins)
{
	return map_put(intercepts, ins.pid, ins);
}

static inline struct intercepted_syscall *get_intercepted_syscall(pid_t pid)
{
	int i = map_get(intercepts, pid);
	if(-1 == i) {
		return NULL;
	}
	return &intercepts.values[i];
}

static inline int pop_intercepted_syscall(struct intercepted_syscall *del)
{
	int k = (del - (struct intercepted_syscall *)&intercepts.values);
	if(0 != map_del_idx(intercepts, k)) {
		printk(KERN_WARNING "monmod <%d>: Unable to remove intercepted "
		       "syscall info at index %d.\n", current->pid, k);
		return 1;
	}
	return 0;
}

static inline bool is_monmod_syscall(long nr)
{
	return __NR_monmod_init == nr || __NR_monmod_reprotect == nr;
}

void custom_syscall_enter(void *__data, struct pt_regs *regs, long id);
int custom_syscall_exit(void *__data, struct pt_regs *regs, long return_value);

#endif