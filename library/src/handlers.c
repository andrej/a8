#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "util.h"
#include "handlers.h"
#include "handler_table.h"
#include "serialization.h"

#include "handler_table_definitions.h"

/* Helpers */

#define get_di(arg_i) ({ \
	struct descriptor_info *di = env_get_canonical_descriptor_info( \
		env, actual->args[arg_i]); \
	if(NULL == di) { \
		return DISPATCH_ERROR; \
	} \
	di; \
})

#define remap_fd(di, arg_i) { \
	actual->args[arg_i] = di->local_fd; \
}

#define alloc_scratch(sz) { \
	*scratch = calloc(sz, 1); \
	if(NULL == scratch) { \
		return DISPATCH_ERROR; \
	} \
}

#define free_scratch() { \
	if(NULL != *scratch) { \
		free(*scratch); \
	} \
}

#define dispatch_leader_if_needed(di, addl_flags) ({ \
	int flags = addl_flags; \
	if(di->flags & DI_OPENED_ON_LEADER) { \
		flags |= DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION; \
	} else { \
		flags |= DISPATCH_EVERYONE; \
	} \
	flags; \
})

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

SYSCALL_ENTER_PROT(default_arg1_fd)
{
	struct descriptor_info *di = get_di(0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

/* ************************************************************************** *
 * brk                                                                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(brk)
{
	/* We cannot compare pointer values since they are architecture-
	   dependent, but we will check whether brk was called with a NULL
	   argument on all platforms. */
	canonical->args[0] = ((void *)canonical->args[0] == NULL ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(char);
	return DISPATCH_EVERYONE | DISPATCH_DEFERRED_CHECK;
}


/* ************************************************************************** *
 * access                                                                     *
 *                                                                            *
 * int access(const char *pathname, int mode);                                *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(access)
{
	// TODO check if pathname should only be access-ed on leader, like in
	// openat handlers
	alloc_scratch(sizeof(struct type));
	struct type *string_type = (struct type *)*scratch;
	canonical->arg_types[0] = POINTER_TYPE(string_type);
	*string_type            = STRING_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(access)
{
	free_scratch();
}


/* ************************************************************************** *
 * open                                                                       *
 *                                                                            *
 * int open(const char *pathname, int flags, mode_t mode);                    *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(open)
{
	/* Move arguments to canonical form: openat */
	canonical->args[3] = canonical->args[2];  // mode
	canonical->args[2] = canonical->args[1];  // flags 
	canonical->args[1] = canonical->args[0];  // pathname
	canonical->args[0] = AT_FDCWD; // dirfd
	return SYSCALL_ENTER(openat)(env, handler, actual, canonical, scratch);
}


/* ************************************************************************** *
 * openat                                                                     *
 *                                                                            *
 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(openat)
{
	alloc_scratch(sizeof(struct type));
	struct type *string_type = (struct type *)*scratch;

	int flags = canonical->args[2];

	/* Move arguments to canonical form: openat */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = STRING_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(string_type);
	           *string_type = STRING_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	if(flags & (O_CREAT)) { // O_TMPFILE
		canonical->arg_types[3] = IMMEDIATE_TYPE(mode_t);
	} else {
		canonical->arg_types[3] = IGNORE_TYPE();
	}
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	const char *pathname = (const char *)canonical->args[1];
	const char dev_prefix[] = "/dev/";
	// TODO Fix this for relative paths
	if(strncmp(pathname, dev_prefix, sizeof(dev_prefix)-1) == 0) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		       | DISPATCH_NEEDS_REPLICATION;
	}

	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(openat)
{
	struct descriptor_info *di;
	int canonical_fd = -1;
	int i = 0;
	if(dispatch & DISPATCH_EVERYONE) {
		i = env_add_local_descriptor(env, actual->ret, 
		                             DI_OPENED_LOCALLY);
	} else if(env->is_leader) {
		i = env_add_local_descriptor(env, actual->ret, 
		                             DI_OPENED_ON_LEADER);
	} else {
		i = env_add_local_descriptor(env, -1, DI_OPENED_ON_LEADER);
	}
	di = &env->descriptors[i];
	actual->ret = di->canonical_fd;
	free_scratch();
	return;
}


/* ************************************************************************** *
 * close                                                                      *
 *                                                                            *
 * int close(int fd);                                                         *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(close)
{
	struct descriptor_info *di = get_di(0);
	*scratch = (void *)di;
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	remap_fd(di, 0);
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(close)
{
	struct descriptor_info *di = (struct descriptor_info *)*scratch;
	if(0 == *(int *)&actual->ret) {
		env_del_descriptor(env, di);
	}
}


/* ************************************************************************** *
 * mmap                                                                       * 
 *                                                                            *
 * void *mmap(void *addr, size_t length, int prot, int flags,                 *
 *            int fd, off_t offset);                                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(mmap)
{
	struct descriptor_info *di = get_di(4);
	if(di->flags & DI_OPENED_ON_LEADER) {
		/* A memory-mapped file must be open locally; we do not support
		   a "remote" memory-mapped file. */
		return DISPATCH_ERROR;
	}

	canonical->args[0] = ((void *)canonical->args[0] == NULL ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(size_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->arg_types[4] = DESCRIPTOR_TYPE();
	remap_fd(di, 4);

	canonical->arg_types[5] = IMMEDIATE_TYPE(off_t);

	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}


/* ************************************************************************** *
 * munmap                                                                     * 
 *                                                                            *
 * int munmap(void *addr, size_t length);                                     *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(munmap)
{
	canonical->args[0] = ((void *)canonical->args[0] == NULL ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(size_t);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}


/* ************************************************************************** *
 * read                                                                       * 
 *                                                                            *
 * ssize_t read(int fd, void *buf, size_t count);                             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(read)
{
	int fd = actual->args[0];
	alloc_scratch(sizeof(struct type));
	struct type *ref_types = (struct type *)*scratch;

	/* Remap fd. */
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	/* Argument 1*/
	canonical->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		   ref_types[0] = BUFFER_TYPE((size_t)canonical->args[2]);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;

	/* Argument 3*/
	canonical->arg_types[2] = IMMEDIATE_TYPE(ssize_t);
	
	/* Return Type*/
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(read)
{
	free_scratch();
}


/* ************************************************************************** *
 * readv                                                                      * 
 *                                                                            *
 * #include <sys/uio.h>                                                       * 
 *                                                                            *
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);                * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(readv)
{
	int iovcnt = canonical->args[2];
	struct iovec *iov = (struct iovec *)canonical->args[1];
	if(0 > iovcnt) {
		return DISPATCH_ERROR;
	}

	/* Remap fd. */
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	/* Allocate scratch space for type. */
	const size_t n_types = 1 + 2*iovcnt;
	const size_t n_buffer_references = iovcnt;
	alloc_scratch(sizeof(struct type) * n_types
	              + sizeof(struct buffer_reference) * n_buffer_references);
	struct type *ref_types = (struct type *)*scratch;
	struct buffer_reference *buf_refs = (struct buffer_reference *)
			(*scratch + sizeof(struct type) * n_types);


	/* Argument 1 */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		   ref_types[0] = BUFFER_TYPE(sizeof(struct iovec) * iovcnt,
		                              n_buffer_references,
					      buf_refs);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;

	for(size_t i = 0; i < iovcnt; i++) {
		ref_types[1+2*i] = POINTER_TYPE(&ref_types[2+2*i]);
		ref_types[2+2*i] = BUFFER_TYPE(iov[i].iov_len);
		buf_refs[i] = (struct buffer_reference)
		              {.offset = (void *)&iov[i].iov_base - (void*)iov, 
		               .type = &ref_types[1+2*i]};
	}

	/* Argument 3*/
	canonical->arg_types[2] = IMMEDIATE_TYPE(ssize_t);

	/* Return Type */
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(readv)
{
	free_scratch();
}


/* ************************************************************************** *
 * write                                                                      * 
 *                                                                            *  
 * ssize_t write(int fd, const void *buf, size_t count);                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(write)
{
	/* Remap fd. */
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	/* Argument types. */
	alloc_scratch(sizeof(struct type));
	struct type *ref_types = (struct type *)*scratch;

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		ref_types[0] = BUFFER_TYPE((size_t)canonical->args[2]);
	canonical->arg_types[2] = IMMEDIATE_TYPE(size_t);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(write)
{
	if(NULL != *scratch) {
		free(*scratch);
	}
}


/* ************************************************************************** *
 * writev                                                                     * 
 *                                                                            *
 * #include <sys/uio.h>                                                       * 
 *                                                                            *
 * ssize_t writev(int fildes, const struct iovec *iov, int iovcnt);           *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(writev)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	int iovcnt = canonical->args[2]; // == n_references
	const struct iovec *iov = (const struct iovec *)canonical->args[1];

	/* Allocate space for types. */
	const size_t n_types = 1 + 2*iovcnt;
	const size_t n_buffer_references = iovcnt;
	alloc_scratch(sizeof(struct type) * n_types
	              + sizeof(struct buffer_reference) * n_buffer_references);
	struct type *ref_types = (struct type *)*scratch;
	struct buffer_reference *buf_refs = (struct buffer_reference *)
			(*scratch + sizeof(struct type) * n_types);
	/* Argument 1 */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		   ref_types[0] = BUFFER_TYPE(sizeof(struct iovec) * iovcnt, 
		                              iovcnt, buf_refs);

	for(int i = 0; i < iovcnt; i++) {
		ref_types[2*i+1] = POINTER_TYPE(&ref_types[2*i+2]);
		ref_types[2*i+2] = BUFFER_TYPE(iov[i].iov_len);
		buf_refs[i] = (struct buffer_reference){
			.offset = (void *)&iov[i].iov_base - (void *)iov,
			.type = &ref_types[2*i+1]
		};
	}

	/* Argument 3 */
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);

	/* Return Type */
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(writev)
{
	free_scratch();
}


/* ************************************************************************** *
 * fstat                                                                      * 
 *                                                                            *
 * int fstat(int fildes, struct stat *buf);                                   * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fstat)
{
	struct descriptor_info *di = get_di(0);
	alloc_scratch(sizeof(struct stat));
	struct type *stat_buf_type = (struct type *)*scratch;

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(stat_buf_type);
	*stat_buf_type          = BUFFER_TYPE(sizeof(struct stat));
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(fstat)
{
	free_scratch();
}
