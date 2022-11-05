#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

int read_regs(pid_t pid, struct user_regs_struct *into);
void print_regs(struct user_regs_struct *regs);

#endif