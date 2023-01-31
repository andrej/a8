#ifndef CUSTOM_SYSCALLS_H
#define CUSTOM_SYSCALLS_H

#include "arch.h"
#include "tracee_info.h"

//#define __NR_monmod_init        (MAX_SYSCALL_NO+3)
//#define __NR_monmod_reprotect   (MAX_SYSCALL_NO+4)
// TODO: Put these + function signatures into a common kernel/userspace header
#define __NR_monmod_init        328
#define __NR_monmod_reprotect   329
#define __NR_monmod_destroy     330

static inline bool is_monmod_syscall(long nr)
{
	return __NR_monmod_init == nr || __NR_monmod_reprotect == nr
	       || __NR_monmod_destroy == nr;
}

void custom_syscall_enter(struct pt_regs *regs, long id,
                          struct tracee *tracee);
void custom_syscall_exit(struct pt_regs *regs, long return_value, 
                         struct tracee *tracee);

struct tracee *sys_monmod_init_special_entry(struct tracee *tracee);

#endif