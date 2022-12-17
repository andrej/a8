#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>

#include "util.h"
#include "handlers.h"
#include "handler_table.h"
#include "serialization.h"

#include "handler_table_definitions.h"

struct syscall_handler const *get_handler(long no)
{
	const size_t n_handlers =
		sizeof(syscall_handlers_arch)/sizeof(syscall_handlers_arch[0]);
	no -= MIN_SYSCALL_NO;
	if(0 > no || no >= n_handlers) {
		return NULL;
	}
	return syscall_handlers_arch[no];
}


/* ************************************************************************** *
 * default                                                                    *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(default)
{
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}


/* ************************************************************************** *
 * brk                                                                        *
 * ************************************************************************** */

const struct type brk_arg_1 = 
	{.kind = IMMEDIATE, .immediate = {sizeof(void *)}};

const struct type * const brk_arg_types [] = {
	&brk_arg_1,
	NULL
};

SYSCALL_ENTER_PROT(brk)
{
	return DISPATCH_EVERYONE | DISPATCH_DEFERRED_CHECK;
}


/* ************************************************************************** *
 * open                                                                       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(open)
{
	//int fd = args[0];
	//add_fd(env, fd);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(open)
{
	int fd = args[0];
	return;
}

SYSCALL_ENTER_PROT(socket)
{
	// TODO
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(socket)
{
	// TODO
	return;
}

SYSCALL_ENTER_PROT(read)
{
	//int fd = remap_fd(env, args[0]);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(read)
{
	return;
}


/* write
   ssize_t write(int fd, const void *buf, size_t count); */


SYSCALL_ENTER_PROT(write)
{
	if(0 > args[2]) {
		return DISPATCH_ERROR;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_GET_ARG_TYPES_PROT(write)
{
	struct type arg_types[N_SYSCALL_ARGS] = {};
	arg_types[0] =
		(struct type){IMMEDIATE, .immediate = {sizeof(int)}};
	arg_types[1] = 
		(struct type){BUFFER, .buffer = {(size_t)args[2]}};
	arg_types[2] = 
		(struct type){IMMEDIATE, .immediate = {sizeof(size_t)}};
	return (struct arg_types) { *arg_types };
}

SYSCALL_EXIT_PROT(write)
{
	return;
}


/* writev 

   #include <sys/uio.h>

   ssize_t writev(int fildes, const struct iovec *iov, int iovcnt); */

SYSCALL_ENTER_PROT(writev)
{
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_GET_ARG_TYPES_PROT(writev)
{
	struct arg_types arg_types = {};

	/* Argument 1 */
	arg_types.arg_types[0] = 
		(struct type){IMMEDIATE, .immediate = {sizeof(int)}};

	/* Argument 2 */
	const struct iovec *iov = (const struct iovec *)args[1];
	int iovcnt = args[2]; // == n_references
	size_t buf_len = sizeof(struct iovec) * iovcnt;
	struct buffer_reference *references = 
		calloc(sizeof(struct buffer_reference), iovcnt);
	struct type *ref_types = calloc(sizeof(struct type), 2*iovcnt + 1);
	if(NULL == references || NULL == ref_types) {
		return (struct arg_types) { };
	}
	ref_types[0] = 
		(struct type){BUFFER, .buffer = {buf_len, iovcnt, references}};
	arg_types.arg_types[1] = 
		(struct type){POINTER, .pointer = {&ref_types[0]}};

	for(int i = 0; i < iovcnt; i++) {
		ref_types[2*i+2] = (struct type){
			BUFFER, .buffer = {iov[i].iov_len}
		};
		ref_types[2*i+1] = (struct type) {
			POINTER, .pointer = {&ref_types[2*i+2]}
		};
		references[i] = (struct buffer_reference){
			.offset = (void *)&iov[i].iov_base - (void *)iov,
			.type = &ref_types[2*i+1]
		};
	}

	/* Argument 3 */
	arg_types.arg_types[2] = 
		(struct type){IMMEDIATE, .immediate = {sizeof(int)}};

	return arg_types;
}

SYSCALL_FREE_ARG_TYPES_PROT(writev)
{
	if(arg_types[1].buffer.n_references > 0) {
		free(arg_types[1].buffer.references[0].type);
		free(arg_types[1].buffer.references);
	}
}

SYSCALL_EXIT_PROT(writev)
{
}

