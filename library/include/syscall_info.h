#ifndef SYSCALL_INFO_H
#define SYSCALL_INFO_H

#include <stdint.h>
#include "arch.h"
#include "serialization.h"

#define ARG_FLAG_NONE        0x0
/* This flag indicates that a system call will interpret this argument as a 
   pointer and write back to it. Therefore, the contents pointed to by the
   pointer are not cross-checked -- they will be overwritten by the system call
   either way. */
#define ARG_FLAG_WRITE_ONLY  0x1

/* This flag indicates that the argument points to a buffer that was only
   written to in the leader -- it must be replicated in followers. */
#define ARG_FLAG_REPLICATE   0x2

/* Arguments with this flag are a descriptor that should be remapped. */
#define ARG_REMAP_FD       0x2

struct syscall_info {
	uint64_t no;
	long args[N_SYSCALL_ARGS];
	int arg_flags[N_SYSCALL_ARGS];
	struct type arg_types[N_SYSCALL_ARGS];
	long ret;
	int ret_flags;
	struct type ret_type;
};

#endif