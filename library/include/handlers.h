#ifndef HANDLERS_H
#define HANDLERS_H

#include "arch.h"
#include "serialization.h"
#include "environment.h"

/* 1. Syscall entry
      Callback performs: Arg serialization/normalization + argument remapping
      Callback returns: Dispatch type, canonical syscall with arguments
   2. Main function cross-checks canonical syscall buffer. Only dispatches if
      all agree.
      Dispatches local system call execution if needed.
   3. Syscall exit
      Callback performs: Bookkeeping for argument remapping,
      Result propagation
*/

#define DISPATCH_ERROR           0x0
#define DISPATCH_EVERYONE        0x1
#define DISPATCH_LEADER          0x2
#define DISPATCH_UNCHECKED       0x4
#define DISPATCH_CHECKED         0x8
#define DISPATCH_DEFERRED_CHECK 0x10

struct arg_types {
	struct type arg_types[N_SYSCALL_ARGS];
};

struct syscall_handler {
	long canonical_no;
	long arch_no;
	int (*enter)(struct environment *, long *, long[N_SYSCALL_ARGS]);
	void (*exit)(struct environment *, long, long[N_SYSCALL_ARGS], long *);
	struct arg_types (*get_arg_types)(struct environment *, long, 
	                             long[N_SYSCALL_ARGS]);
	void (*free_arg_types)(struct type[N_SYSCALL_ARGS]);
	const char *name;
};

#define SYSCALL_ENTER(name) __ ## name ## _enter 
#define SYSCALL_EXIT(name) __ ## name ## _exit
#define SYSCALL_GET_ARG_TYPES(name) __ ## name ## _get_arg_types
#define SYSCALL_FREE_ARG_TYPES(name) __ ## name ## _free_arg_types
#define SYSCALL_ENTER_PROT(name) \
	int __ ## name ## _enter (struct environment *env, long *no, \
	                          long args[N_SYSCALL_ARGS])
#define SYSCALL_EXIT_PROT(name) \
	void __ ## name ## _exit (struct environment *env, long no, \
	                          long args[N_SYSCALL_ARGS], long *ret)
#define SYSCALL_GET_ARG_TYPES_PROT(name) \
	struct arg_types __ ## name ## _get_arg_types( \
		struct environment *env, long no, long args[N_SYSCALL_ARGS])
#define SYSCALL_FREE_ARG_TYPES_PROT(name) \
	void __ ## name ## _free_arg_types( \
		struct type arg_types[N_SYSCALL_ARGS])

extern const struct syscall_handler * const syscall_handlers_arch[];
extern const struct syscall_handler * const syscall_handlers_canonical[];

struct syscall_handler const *get_handler(long no);

#endif