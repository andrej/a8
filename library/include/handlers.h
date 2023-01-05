#ifndef HANDLERS_H
#define HANDLERS_H

#include "arch.h"
#include "serialization.h"
#include "environment.h"

/**
 * The system call cannot be dispatched because the entry handler errored. This
 * will lead to termination of the program.
 */
#define DISPATCH_ERROR              0x1
/**
 * The system call will be executed locally on every host, with the arguments
 * in the `actual` struct.
 */
#define DISPATCH_EVERYONE           0x2
/**
 * The system call will be executed only on the leader host. The 
 * DISPATCH_NEEDS_REPLICATION flag nees to be ORed in if the results of the
 * system call on the leader should also be replicated to all other nodes.
 */
#define DISPATCH_LEADER             0x4
/**
 * The system call arguments need not be cross-checked.
 */
#define DISPATCH_UNCHECKED          0x8
/**
 * Cross-check system call arguments in the `canonical` struct, and only
 * dispatch the system call if arguments match.
 */
#define DISPATCH_CHECKED           0x10
/**
 * Currently not implemented. Future potential optimization would allow to
 * execute a benign system call speculatively but still check its arguments
 * later on, as soon as the first critical system call is encountered.
 */
#define DISPATCH_DEFERRED_CHECK    0x20
/**
 * Take the return value of the leader node, and replicate its results to all
 * other nodes. Note that ARG_FLAG_REPLICATE needs to be set on the return
 * value flags for this to take place. Any arguments with ARG_FLAG_REPLICATE
 * will also be replicated. 
 */
#define DISPATCH_NEEDS_REPLICATION 0x40
/**
 * Do not execute this system call anywhere (not on leader or other hosts), and
 * continue with the exit handler.
 */
#define DISPATCH_SKIP              0x80

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

struct syscall_handler {
	long canonical_no;
	long arch_no;
	int (*enter)(struct environment *, const struct syscall_handler *,
	             struct syscall_info *, struct syscall_info *, void **);
	void (*post_call)(struct environment *, const struct syscall_handler *,
			  int, struct syscall_info *, struct syscall_info *,
			   void **);
	void (*exit)(struct environment *, const struct syscall_handler *, int,
	             struct syscall_info *, struct syscall_info *, void **);
	const char *name;
};

#define SYSCALL_ENTER(name) __ ## name ## _enter 
#define SYSCALL_POST_CALL(name) __ ## name ## _post_call
#define SYSCALL_EXIT(name) __ ## name ## _exit
#define SYSCALL_ENTER_PROT(name) \
	int __ ## name ## _enter (struct environment *env, \
	                          const struct syscall_handler *handler, \
	                          struct syscall_info *actual, \
	                          struct syscall_info *canonical, \
	                          void **scratch)
#define SYSCALL_POST_CALL_PROT(name) \
	void __ ## name ## _post_call (struct environment *env, \
	                               const struct syscall_handler *handler, \
	                               int dispatch, \
	                               struct syscall_info *actual, \
	                               struct syscall_info *canonical, \
	                               void **scratch)
#define SYSCALL_EXIT_PROT(name) \
	void __ ## name ## _exit (struct environment *env, \
	                          const struct syscall_handler *handler, \
				  int dispatch, \
	                          struct syscall_info *actual, \
	                          struct syscall_info *canonical, \
	                          void **scratch)

extern const struct syscall_handler * const syscall_handlers_arch[];
extern const struct syscall_handler * const syscall_handlers_canonical[];

/* See comment in replication.h for replication_buffer. */
#define HANDLER_SCRATCH_BUFFER_SZ 4096
extern char handler_scratch_buffer[HANDLER_SCRATCH_BUFFER_SZ];

struct syscall_handler const *get_handler(long no);

#endif