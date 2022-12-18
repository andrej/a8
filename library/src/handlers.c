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

SYSCALL_ENTER_PROT(default_checked)
{
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_ENTER_PROT(default_unchecked)
{
	return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
}

SYSCALL_NORMALIZE_ARGS_PROT(default_1_arg)
{
	normal->arg_types[0] = IMMEDIATE_TYPE(long);
	return 0;
}

SYSCALL_NORMALIZE_ARGS_PROT(default_2_args)
{
	normal->arg_types[0] = IMMEDIATE_TYPE(long);
	normal->arg_types[1] = IMMEDIATE_TYPE(long);
	return 0;
}

SYSCALL_NORMALIZE_ARGS_PROT(default_3_args)
{
	normal->arg_types[0] = IMMEDIATE_TYPE(long);
	normal->arg_types[1] = IMMEDIATE_TYPE(long);
	normal->arg_types[2] = IMMEDIATE_TYPE(long);
	return 0;
}

SYSCALL_ENTER_PROT(default_checked_arg1_fd)
{
	int fd = args[0];
	struct descriptor_info *di = env_get_local_descriptor_info(env, fd);
	if(NULL == di) {
		return DISPATCH_ERROR;
	}
	if(!(di->flags & DI_OPENED_LOCALLY)) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		       | DISPATCH_NEEDS_REPLICATION;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

/* ************************************************************************** *
 * brk                                                                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(brk)
{
	return DISPATCH_EVERYONE | DISPATCH_DEFERRED_CHECK;
}

SYSCALL_NORMALIZE_ARGS_PROT(brk)
{
	/* We cannot compare pointer values since they are architecture-
	   dependent, but we will check whether brk was called with a NULL
	   argument on all platforms. */
	normal->args[0] = ((void *)normal->args[0] == NULL ? 0 : 1);
	normal->arg_types[0] = IMMEDIATE_TYPE(char);
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

/* ************************************************************************** *
 * read                                                                       * 
 *                                                                            *
 * ssize_t read(int fd, void *buf, size_t count);                             *
 * ************************************************************************** */

SYSCALL_NORMALIZE_ARGS_PROT(read)
{
	struct type *ref_types = calloc(sizeof(struct type), 1);
	if(NULL == ref_types) {
		return 1;
	}

	/* Argument 1*/
	normal->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	normal->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		ref_types[0] = BUFFER_TYPE((size_t)normal->args[2]);
	normal->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;

	/* Argument 3*/
	normal->arg_types[2] = IMMEDIATE_TYPE(ssize_t);
	return 0;
}

SYSCALL_FREE_NORMALIZED_ARGS_PROT(read)
{
	if(POINTER == normal->arg_types[1].kind) {
		free(normal->arg_types[1].pointer.type);
	}
}

SYSCALL_EXIT_PROT(read)
{
	return;
}


/* ************************************************************************** *
 * readv                                                                      * 
 *                                                                            *
 * #include <sys/uio.h>                                                       * 
 *                                                                            *
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);                * 
 * ************************************************************************** */

SYSCALL_NORMALIZE_ARGS_PROT(readv)
{
	int iovcnt = normal->args[2];
	struct iovec *iov = (struct iovec *)normal->args[1];
	if(0 > iovcnt) {
		return 1;
	}

	const size_t n_types = 1 + 2*iovcnt;
	const size_t n_buffer_references = iovcnt;
	char *buf = calloc(sizeof(struct type) * n_types
	                   + sizeof(struct buffer_reference) 
			     * n_buffer_references,
			   1);
	if(NULL == buf) {
		return 1;
	}
	struct type *ref_types = (struct type *)buf;
	struct buffer_reference *buf_refs = (struct buffer_reference *)
			(buf + sizeof(struct type) * n_types);

	/* Argument 1*/
	normal->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	normal->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		ref_types[0] = BUFFER_TYPE(sizeof(struct iovec) * iovcnt,
		                           n_buffer_references,
					   buf_refs);
	normal->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;

	for(size_t i = 0; i < iovcnt; i++) {
		ref_types[1+2*i] = POINTER_TYPE(&ref_types[2+2*i]);
		ref_types[2+2*i] = BUFFER_TYPE(iov[i].iov_len);
		buf_refs[i] = (struct buffer_reference)
		              {.offset = (void *)&iov[i].iov_base - (void*)iov, 
		               .type = &ref_types[1+2*i]};
	}

	/* Argument 3*/
	normal->arg_types[2] = IMMEDIATE_TYPE(ssize_t);
	return 0;
}

SYSCALL_FREE_NORMALIZED_ARGS_PROT(readv)
{
	if(POINTER == normal->arg_types[1].kind) {
		free(normal->arg_types[1].pointer.type);
	}
}


/* ************************************************************************** *
 * write                                                                      * 
 *                                                                            *  
 * ssize_t write(int fd, const void *buf, size_t count);                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(write)
{
	if(0 > args[2]) {
		return DISPATCH_ERROR;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_NORMALIZE_ARGS_PROT(write)
{
	struct type *ref_types = calloc(sizeof(struct type), 1);
	if(NULL == ref_types) {
		return 1;
	}
	normal->arg_types[0] = DESCRIPTOR_TYPE();
	normal->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		ref_types[0] = BUFFER_TYPE((size_t)normal->args[2]);
	normal->arg_types[2] = IMMEDIATE_TYPE(size_t);
	return 0;
}

SYSCALL_FREE_NORMALIZED_ARGS_PROT(write)
{
	if(POINTER == normal->arg_types[1].kind) {
		free(normal->arg_types[1].pointer.type);
	}
}

SYSCALL_EXIT_PROT(write)
{
	return;
}


/* ************************************************************************** *
 *  writev                                                                    * 
 *                                                                            *
 *  #include <sys/uio.h>                                                      * 
 *                                                                            *
 *  ssize_t writev(int fildes, const struct iovec *iov, int iovcnt);          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(writev)
{
	if(0 > args[2]) {
		return DISPATCH_ERROR;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_NORMALIZE_ARGS_PROT(writev)
{

	/* Argument 1 */
	normal->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	const struct iovec *iov = (const struct iovec *)normal->args[1];
	int iovcnt = normal->args[2]; // == n_references
	size_t buf_len = sizeof(struct iovec) * iovcnt;
	struct buffer_reference *references = 
		calloc(sizeof(struct buffer_reference), iovcnt);
	struct type *ref_types = calloc(sizeof(struct type), 2*iovcnt + 1);
	if(NULL == references || NULL == ref_types) {
		return 1;
	}

	normal->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		ref_types[0] = BUFFER_TYPE(buf_len, iovcnt, references);

	for(int i = 0; i < iovcnt; i++) {
		ref_types[2*i+1] = POINTER_TYPE(&ref_types[2*i+2]);
		ref_types[2*i+2] = BUFFER_TYPE(iov[i].iov_len);
		references[i] = (struct buffer_reference){
			.offset = (void *)&iov[i].iov_base - (void *)iov,
			.type = &ref_types[2*i+1]
		};
	}

	/* Argument 3 */
	normal->arg_types[2] = IMMEDIATE_TYPE(int);

	return 0;
}

SYSCALL_FREE_NORMALIZED_ARGS_PROT(writev)
{
	if(normal->arg_types[1].buffer.n_references > 0) {
		free(normal->arg_types[1].buffer.references[0].type);
		free(normal->arg_types[1].buffer.references);
	}
}

