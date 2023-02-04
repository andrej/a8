#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <limits.h>

#include "util.h"
#include "handlers.h"
#include "handler_table.h"
#include "serialization.h"
#include "handler_data_types.h"
#include "environment.h"

#include "handler_table_definitions.h"

/* Helpers */

char handler_scratch_buffer[HANDLER_SCRATCH_BUFFER_SZ] = {};
void *next_preallocated = handler_scratch_buffer;

#define get_di(arg_i) ({ \
	struct descriptor_info *di = env_get_canonical_descriptor_info( \
		env, canonical->args[arg_i]); \
	if(NULL == di) { \
		return DISPATCH_ERROR; \
	} \
	di; \
})

#define remap_fd(di, arg_i) { \
	actual->args[arg_i] = (di)->local_fd; \
}

#define alloc_scratch(sz) { \
	if(sz < handler_scratch_buffer + sizeof(handler_scratch_buffer)  \
	            - (char *)next_preallocated) { \
		*scratch = next_preallocated; \
		*(size_t *)(next_preallocated + sz) = sz; \
		next_preallocated += sz + sizeof(size_t); \
	} else { \
		*scratch = safe_malloc(sz + sizeof(size_t)); \
		*(size_t *)*scratch = sz + sizeof(size_t); \
		*scratch = (*scratch) + sizeof(size_t); \
		if(NULL == scratch) { \
			return DISPATCH_ERROR; \
		} \
	} \
}

#define prev_preallocated() ({ \
	void *res =  handler_scratch_buffer; \
	if(next_preallocated != handler_scratch_buffer) { \
		size_t prev_sz = *(size_t *)(next_preallocated \
		                             - sizeof(size_t)); \
		res = next_preallocated - prev_sz - sizeof(size_t); \
	} \
	res; \
})

#define free_scratch() { \
	void *prev_pa = prev_preallocated(); \
	if(NULL != scratch && NULL != *scratch \
	   && prev_pa != *scratch) { \
	   	*scratch = (*scratch) - sizeof(size_t); \
	   	size_t sz = *(size_t *)(*scratch); \
		safe_free(*scratch, sz); \
	} else if(prev_pa == *scratch) { \
		next_preallocated = prev_pa; \
	} \
}

#define dispatch_leader_if_needed(di, addl_flags) ({ \
	int flags = addl_flags; \
	if(NULL != (di) && (di)->flags & DI_OPENED_ON_LEADER) { \
		flags |= DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION; \
	} else { \
		flags |= DISPATCH_EVERYONE; \
	} \
	flags; \
})


/* TODO: monitor opens some file descriptors itself, e.g. for logging, 
   sockets for intra-monitor commmunication, etc. If the variant requests to
   use these fds via dup2/dup3, we currently error (could also remap to 
   arbitrary fd instead, transparently to variant). */
#define is_monitor_fd(fd) \
	0

#define post_call_error() { \
	if(actual->ret >= 0) { \
		actual->ret = -ENOSYS; \
	} \
	return; \
}

static inline int get_dispatch_by_path(const char *path)
{
	// Check path
	char pathname[PATH_MAX];
	if(NULL == realpath(path, pathname)) {
		return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	/* If realpath() errored, it is likely because the path does not
		exist. Just dispatch it for everyone and let them handle the
		error. */
	const char dev_prefix[] = "/dev/";
	const char proc_prefix[] = "/proc/";
	const char etc_localtime[] = "/etc/localtime";
	const char etc_group[] = "/etc/group";
	const char zoneinfo[] = "/usr/share/zoneinfo/";
	if(strncmp(pathname, dev_prefix, sizeof(dev_prefix)-1) == 0) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		| DISPATCH_NEEDS_REPLICATION;
	} else if(strncmp(pathname, proc_prefix, sizeof(proc_prefix)-1) == 0
	          || strncmp(pathname, etc_localtime, sizeof(etc_localtime)-1
    		      == 0)
		  || strncmp(pathname, etc_group, sizeof(etc_group)-1) == 0
		  || strncmp(pathname, zoneinfo, sizeof(zoneinfo)-1) == 0
		  || NULL != strstr(pathname, "libnss") // FIXME
		  || NULL != strstr(pathname, "libnsl")
		  ) {
		return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

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

SYSCALL_ENTER_PROT(default_checked_arg1) {
	canonical->arg_types[0] = IMMEDIATE_TYPE(long);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_ENTER_PROT(default_arg1_fd)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(default_creates_fd_exit)
{
	struct descriptor_info *di;
	enum descriptor_type type;
	if(0 > actual->ret) {
		return;
	}
#if VERBOSITY >= 3
	SAFE_LOGF(log_fd, "%s adding descriptor.\n", handler->name);
#endif
	int flags = 0;
	int local_fd = -1;
	if(dispatch & DISPATCH_EVERYONE) {
		flags |= DI_OPENED_LOCALLY;
		local_fd = actual->ret;
	} else if(env->is_leader) {
		flags |= DI_OPENED_ON_LEADER;
		local_fd = actual->ret;
	} else {
		flags = DI_OPENED_ON_LEADER;
	}
	if(dispatch & DISPATCH_UNCHECKED) {
		flags |= DI_UNCHECKED;
	}
	type = (enum descriptor_type)FILE_DESCRIPTOR;
	switch(canonical->no) {
		case SYSCALL_socket_CANONICAL:
		case SYSCALL_accept4_CANONICAL:
			type = SOCKET_DESCRIPTOR;
			break;
		case SYSCALL_epoll_create_CANONICAL:
		case SYSCALL_epoll_create1_CANONICAL:
			type = EPOLL_DESCRIPTOR;
			break;
	}
	di = env_add_local_descriptor(env, local_fd, flags, type);
	actual->ret = canonical_fd_for(env, di);
	free_scratch();
	return;
}

SYSCALL_EXIT_PROT(default_free_scratch)
{
	free_scratch();
}

/* ************************************************************************** *
 * brk                                                                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(brk)
{
	/* The brk system call should remain unmonitored (for performance
	   reasons best in the kernel module settings). libc calloc uses
	   locking, and when our monitor intercepts brk and tries to allocate
	   memory itself, this can lead to a deadlock. */
	return DISPATCH_ERROR;
}


/* ************************************************************************** *
 * access                                                                     *
 *                                                                            *
 * int access(const char *pathname, int mode);                                *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(access)
{
	// Redirect to facessat handlers
	canonical->args[2] = canonical->args[1];
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = AT_FDCWD;
	canonical->no = SYSCALL_faccessat_CANONICAL;
	return SYSCALL_ENTER(faccessat)(env, handler, actual, canonical, 
	                                scratch);
}


/* ************************************************************************** *
 * faccessat                                                                  *
 *                                                                            *
 * int faccessat(int dirfd, const char *pathname, int mode);                  *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(faccessat)
{
	int dispatch = get_dispatch_by_path((const char *)canonical->args[1]);
	alloc_scratch(sizeof(struct type));
	if(AT_FDCWD != canonical->args[0]) {
		struct descriptor_info *di = get_di(0);
		remap_fd(di, 0);
	}
	struct type *string_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(string_type);
	*string_type            = STRING_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	return dispatch;
}


/* ************************************************************************** *
 * open                                                                       *
 *                                                                            *
 * int open(const char *pathname, int flags, mode_t mode);                    *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(open)
{
	/* Move arguments to canonical form: openat */
	canonical->no = SYSCALL_openat_CANONICAL;
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
	struct descriptor_info *di = NULL;
	if(AT_FDCWD != canonical->args[0]) {
		get_di(0);
		remap_fd(di, 0);
	}

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

	return get_dispatch_by_path((const char *)canonical->args[1]);

}


/* ************************************************************************** *
 * close                                                                      *
 *                                                                            *
 * int close(int fd);                                                         *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(close)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	*scratch = (void *)di;
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(close)
{
	struct descriptor_info *di = (struct descriptor_info *)*scratch;
	if(0 == *(int *)&actual->ret) {
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "close removing descriptor.%s", "\n");
#endif
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
	int flags = actual->args[3];
	struct descriptor_info *di = NULL;

	if(!(flags & (MAP_ANON | MAP_ANONYMOUS))) {
		di = get_di(4);
		remap_fd(di, 4);
		if(di->flags & DI_OPENED_ON_LEADER) {
			/* A memory-mapped file must be open locally; we do not 
			   support a "remote" memory-mapped file. */
			return DISPATCH_ERROR;
		}
		if(di->flags & DI_UNCHECKED) {
			return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
		}
	}

	canonical->args[0] = ((void *)canonical->args[0] == NULL ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->args[1] = (canonical->args[1] == 0 ? 0 : 1);
	canonical->arg_types[1] = IMMEDIATE_TYPE(size_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->arg_types[4] = DESCRIPTOR_TYPE();

	canonical->arg_types[5] = IMMEDIATE_TYPE(off_t);
	canonical->args[5] = (canonical->args[5] == 0 ? 0 : 1);

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
	canonical->args[1] = (canonical->args[1] == 0 ? 0 : 1);
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

	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
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

	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
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

	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(write)
{
	free_scratch();
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
	
	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(writev)
{
	free_scratch();
}


/* ************************************************************************** *
 * stat                                                                       * 
 *                                                                            *
 * int stat(const char *restrict pathname,                                     *
 *          struct stat *restrict statbuf);                                   * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(stat)
{
	// Forward to fstatat
	canonical->no = SYSCALL_fstatat_CANONICAL;
	canonical->args[3] = 0; // flags
	canonical->args[2] = canonical->args[1]; // statbuf
	canonical->args[1] = canonical->args[0]; // path
	canonical->args[0] = AT_FDCWD;
	actual->no = __NR_newfstatat;
	actual->args[3] = 0; // flags
	actual->args[2] = actual->args[1]; // statbuf
	actual->args[1] = actual->args[0]; // path
	actual->args[0] = AT_FDCWD;
	return SYSCALL_ENTER(fstatat)(env, handler, actual, canonical, scratch);
}

SYSCALL_EXIT_PROT(stat)
{
	SYSCALL_EXIT(fstatat)(env, handler, dispatch, actual,
	             canonical, scratch);
	actual->args[0] = actual->args[1];
	actual->args[1] = actual->args[2];
	actual->args[1] = actual->args[2];
}


/* ************************************************************************** *
 * fstat                                                                      * 
 *                                                                            *
 * int fstat(int fildes, struct stat *buf);                                   * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fstat)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	int dispatch = 0; 
	if(di->flags & DI_UNCHECKED) {
		dispatch = DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	} else {
		/* Metadata of files is likely to cause a false positive 
		   divergence. For example, file time stamps are likely to be 
		   different. Thus, we dispatch all as leader-only currently. */
		dispatch = DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION
		           | DISPATCH_CHECKED;
	}

	alloc_scratch(sizeof(struct type));
	struct type *stat_buf_type = (struct type *)*scratch;

	char *normalized_stat = NULL;
	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
		// fstat is reentrant, so calloc should be fine here
		normalized_stat = calloc(1, NORMALIZED_STAT_STRUCT_SIZE);
		if(NULL == normalized_stat) {
			return DISPATCH_ERROR;
		}
	}

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->args[1]      = (long)normalized_stat;
	canonical->arg_types[1] = POINTER_TYPE(stat_buf_type);
	*stat_buf_type          = BUFFER_TYPE(NORMALIZED_STAT_STRUCT_SIZE);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return dispatch;
}

SYSCALL_POST_CALL_PROT(fstat)
{
	char *normalized_stat = (char *)canonical->args[1];
	if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
		return;
	}
	normalize_stat_struct_into((struct stat *)actual->args[1],
	                           normalized_stat);
}

SYSCALL_EXIT_PROT(fstat)
{
	if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
		return;
	}
	char *normalized_stat = (char *)canonical->args[1];
	denormalize_stat_struct_into(normalized_stat,
	                             (struct stat *)actual->args[1]);
	if(NULL != normalized_stat) {
		free(normalized_stat);
	}
	free_scratch();
}

/* ************************************************************************** *
 * fstatat                                                                 * 
 *                                                                            *
 * int fstatat(int fd, const char *restrict path,                             *
 *             struct stat *restrict buf, int flag);                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fstatat)
{
	struct descriptor_info *di = NULL;
	if(AT_FDCWD != actual->args[0]) {
		get_di(0);
		remap_fd(di, 0);
	}
	alloc_scratch(2 * sizeof(struct type));
	struct type *stat_buf_type = (struct type *)*scratch;
	struct type *str_type = ((struct type *)*scratch) + 1;

	int dispatch = get_dispatch_by_path((const char *)actual->args[1]);
	if(!(dispatch & DISPATCH_UNCHECKED)) {
		/* See fstat docuementation why whe dispatch on leader. */
		dispatch = DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION
		           | DISPATCH_CHECKED;
	}
	if(NULL == (char *)actual->args[2]) {
		return DISPATCH_ERROR;
	}

	char *normalized_stat = NULL;
	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
		// fstatat is reentrant, so calloc should be fine here
		normalized_stat = calloc(1, NORMALIZED_STAT_STRUCT_SIZE);
		if(NULL == normalized_stat) {
			return DISPATCH_ERROR;
		}
	}

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(str_type);
	*str_type               = STRING_TYPE();
	canonical->args[2]      = (long)normalized_stat;
	canonical->arg_types[2] = POINTER_TYPE(stat_buf_type);
	*stat_buf_type          = BUFFER_TYPE(NORMALIZED_STAT_STRUCT_SIZE);
	canonical->arg_flags[2] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return dispatch;
}

SYSCALL_POST_CALL_PROT(fstatat)
{
	char *normalized_stat = (char *)canonical->args[2];
	if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
		return;
	}
	normalize_stat_struct_into((struct stat *)actual->args[2],
	                           normalized_stat);
}

SYSCALL_EXIT_PROT(fstatat)
{
	char *normalized_stat = (char *)canonical->args[2];
	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
		denormalize_stat_struct_into(normalized_stat, 
					(struct stat *)actual->args[2]);
	}
	if(NULL != normalized_stat) {
		free(normalized_stat);
	}
	free_scratch();
}


/* ************************************************************************** *
 * time                                                                       * 
 *                                                                            *
 * time_t time(time_t *tloc);                                                 *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(time)
{
	struct scratch {
		void *gettimeofday_scratch;
		struct timeval tv;
		struct timezone tz;
		time_t *orig_tloc;
	};
	alloc_scratch(sizeof(struct scratch));
	struct scratch *s = (struct scratch *)*scratch;

	/* Remap to gettimeofday. */
	s->orig_tloc = (time_t *)actual->args[0];
	canonical->no      = SYSCALL_gettimeofday_CANONICAL;
	actual->no         = __NR_gettimeofday;
	actual->args[0]    = (long)&s->tv;
	canonical->args[0] = actual->args[0];
	actual->args[1]    = (long)&s->tz;
	canonical->args[1] = actual->args[1]; 
	return SYSCALL_ENTER(gettimeofday)(env, handler, actual, canonical,
	                                   &s->gettimeofday_scratch);
}

SYSCALL_EXIT_PROT(time)
{
	struct scratch {
		void *gettimeofday_scratch;
		struct timeval tv;
		struct timezone tz;
		time_t *orig_tloc;
	};
	struct scratch *s = (struct scratch *)*scratch;

	SYSCALL_EXIT(gettimeofday)(env, handler, dispatch, actual, canonical,
	                           &s->gettimeofday_scratch);

	/* Remap gettimeofday result back to time_t. */
	time_t ret = (time_t)-1;
	if(actual->ret == 0) {
		ret = s->tv.tv_sec;
	}
	if(NULL != s->orig_tloc) {
		*s->orig_tloc = ret;
	}
	actual->ret = ret;

	free_scratch();
}


/* ************************************************************************** *
 * gettimeofday                                                               * 
 *                                                                            *
 * int gettimeofday(struct timeval *restrict tv,                              *
 *                  struct timezone *restrict tz);                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(gettimeofday)
{
	alloc_scratch(2 * sizeof(struct type));
	struct type *buf_types = (struct type *)*scratch;

	canonical->arg_types[0] = POINTER_TYPE(&buf_types[0]);
	buf_types[0]            = BUFFER_TYPE(sizeof(struct timeval));
	canonical->arg_flags[0] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE; 
	canonical->arg_types[1] = POINTER_TYPE(&buf_types[1]);
	buf_types[1]            = BUFFER_TYPE(sizeof(struct timezone));
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE; 
	canonical->ret_type     = IMMEDIATE_TYPE(long);
	canonical->ret_flags    = ARG_FLAG_REPLICATE;

	// TODO Could also check for NULL/non-NULL tv/tz pointers during
	// cross-checking
	return DISPATCH_CHECKED | DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION;
}

SYSCALL_EXIT_PROT(gettimeofday)
{
	free_scratch();
}


/* ************************************************************************** *
 * dup2                                                                       * 
 *                                                                            *
 * int dup2(int oldfd, int newfd);                                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(dup2)
{
	int oldfd = canonical->args[0];
	int newfd = canonical->args[1];
	if(oldfd == newfd) {
		// dup3 returns an error value in this case, dup2 allows it
		actual->ret = oldfd;
		return DISPATCH_SKIP | DISPATCH_CHECKED;
	}

	// Redirect to dup3 handlers
	canonical->no = SYSCALL_dup3_CANONICAL;
	canonical->args[2] = 0; // flags
	
	return SYSCALL_ENTER(dup3)(env, handler, actual, canonical, scratch);
}

SYSCALL_EXIT_PROT(dup2)
{
	if(dispatch & DISPATCH_SKIP) {
		return;
	}
	return SYSCALL_EXIT(dup3)(env, handler, dispatch, actual, canonical, 
	                          scratch);
}


/* ************************************************************************** *
 * dup3                                                                       * 
 *                                                                            *
 * int dup2(int oldfd, int newfd, int flags);                                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(dup3)
{
	alloc_scratch(sizeof(struct descriptor_info *) * 2);
	struct descriptor_info **di = (struct descriptor_info **)*scratch;
	int oldfd = canonical->args[0];
	int newfd = canonical->args[1];

	di[0] = get_di(0);
	di[1] = env_get_canonical_descriptor_info(env, newfd);

	remap_fd(di[0], 0);
	if(NULL != di[1]) {
		/* fd is stdin, stdout, stderr, or was previously opened by the
		   variant. That means it is "owned by" the variant and we can 
		   modify the underlying fd. We must translate the canonical
		   fd to the actually kernel-exposed local fd. */
		remap_fd(di[1], 1);
	} else if(is_monitor_fd(newfd)) {
		/* The fd requested by the variant collides with a file
		   descriptor we cannot close/override. */
		return DISPATCH_ERROR;
	} else {
		/* In this case, dup3 will create a new file descriptor whose
		   canonical number matches the local number -- we can allow
		   this, it does not collide with any other local fds. */
	}

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = DESCRIPTOR_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->ret_type = DESCRIPTOR_TYPE();
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di[0], DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(dup3)
{
	int newfd = canonical->args[1];

	if(0 > actual->ret) {
		goto ret;
	}

	struct descriptor_info **di = (struct descriptor_info **)*scratch;

	if(NULL != di[1]) {
		/* newfd will override a fd previously opened by the variant. 
		   old local fd was closed by a successful dup2 call. */
#if VERBOSITY >= 3
		SAFE_LOGF(log_fd, "dup3 removing descriptor.%s", "\n");
#endif
		env_del_descriptor(env, di[1]);
	}

	int local_fd = -1;
	if(is_open_locally(env, di[0])) {
		local_fd = actual->ret;
	}
#if VERBOSITY >= 3
	SAFE_LOGF(log_fd, "dup3 adding descriptor.%s", "\n");
#endif
	Z_TRY_EXCEPT(env_add_descriptor(env, local_fd, newfd, di[0]->flags,
	                                di[0]->type),
	             newfd = -1);
	
	actual->ret = newfd;

ret:
	free_scratch();
}


/* ************************************************************************** *
 * lseek                                                                      * 
 *                                                                            *
 * off_t lseek(int fd, off_t offset, int whence);                             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(lseek)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(off_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	if(di->flags & DI_UNCHECKED) {
		return dispatch_leader_if_needed(di, DISPATCH_UNCHECKED);
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}


/* ************************************************************************** *
 * socket                                                                     *
 *                                                                            *
 * int socket(int domain, int type, int protocol);                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(socket)
{
	int domain = actual->args[0];
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	if(domain != AF_UNIX) {
		canonical->ret_flags = ARG_FLAG_REPLICATE;
	}
	if(domain == AF_UNIX) {
		return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	}
	return DISPATCH_LEADER | DISPATCH_CHECKED
		| DISPATCH_NEEDS_REPLICATION;
}


/* ************************************************************************** *
 * epoll_create                                                               *
 *                                                                            *
 * int epoll_create(int size);                                                *
 * ************************************************************************** */

/* epolls require a little more special handling on our end.

   The general workflow that a variant expects is as follows:
   
   1. Variant creates an epollfd using epoll_create.
   2. Variant associates (epfd, fd, events) triple with some arbitrary data.
   3. Upon any epoll_wait(epfd ...), when any of the `events` happens on `fd`, 
      the previously registered arbitrary data must be returned.

   This poses the following challenges:
   A. If an `epfd` becomes associated with an `fd` that is only opened on the
      leader (e.g. a socket), the entire `epfd` becomes 'contaminated': any
      call to `epoll_wait` must got to the leader and be replicated.
   B. Any data associated with the (epfd, fd, events) triple must be returned
      exactly as previously registered by `epoll_ctl` upon an `epoll_wait`. We
      cannot 'blindly' replicate the returned data -- the data that was
      previously registered on each variant must be returned, and this data
      might vary from variant to variant.

   We solve this as follows:

   epoll_create(): We assume all epfds will be contaminated and hence only
   create them on the leader.

   epoll_ctl(epfd, EPOLL_CTL_ADD, fd, event): 
     1. Check that event->data matches up across all calls, except for the
        `data` field, which may contain arbitrary data, including pointers,
	and hence cannot be cross-checked
     2. Store a mapping (epfd, fd, event->events) -> event->data. This stores
        the data that we must return upon a subsequent epoll_wait for this fd
	and event->events.
     3. Overwrite the fourth argument (event pointer) to our own 
        (struct epoll_event) with custom data, but same events:
		{.events = copied from original,
		.data = {.fd = fd}}
     4. Remap epfd and fd to kernel values (only in leader, call is not
        excectued on other variants)

   epoll_wait(epfd, events, maxevents, timeout):
     1. Dispatch only on leader and replicate return value and events buffer
     2. Iterate through events buffer. For each event:
        a. Find x = (epfd, fd, event->events) in our map. Copy x->data to
	   events[i].data.
	   This overwrites our custom data and restores the original data that
	   was associated with this event in epoll_ctl(). 
   
   Note:
   - The kernel returns our custom data for all epoll_waits() which we must
     overwrite.
   - Our mappings use canonical file descriptors for everything. The remapping
     happens in the last step, before exit. Canonical file descriptors should
     always match up across variants.
*/

SYSCALL_ENTER_PROT(epoll_create)
{
	canonical->no = SYSCALL_epoll_create1_CANONICAL;
	canonical->args[0] = 0;
	return SYSCALL_ENTER(epoll_create1)(env, handler, actual, canonical, 
	                                    scratch);
}


/* ************************************************************************** *
 * epoll_create1                                                              *
 *                                                                            *
 * int epoll_create(int flags);                                               *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(epoll_create1)
{
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION | DISPATCH_CHECKED;
}


/* ************************************************************************** * 
 * epoll_ctl                                                                  *
 *                                                                            *
 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);        *
 * ************************************************************************** */
 
/* See epoll_create documentation above to see how we handle these calls. */

SYSCALL_ENTER_PROT(epoll_ctl)
{
	struct scratch {
		struct type ref_types[2];
		struct buffer_reference buf_refs[1];
		struct descriptor_info *epfd_di;
		struct descriptor_info *fd_di;
		struct epoll_event custom_event;
	};
	alloc_scratch(sizeof(struct scratch) + NORMALIZED_EPOLL_EVENT_SIZE);
	struct scratch *s = (struct scratch *)*scratch;
	char *normalized_event = (char *)((struct scratch *)*scratch + 1);
	int epfd = canonical->args[0];
	int op = canonical->args[1];
	int fd = canonical->args[2];
	struct epoll_event *event = (struct epoll_event *)actual->args[3];

	/* Define arguement types */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[2] = DESCRIPTOR_TYPE();
	canonical->arg_types[3] = POINTER_TYPE(&s->ref_types[0]);
	canonical->args[3] = (long)normalized_event;
	normalize_epoll_event_structs_into(
				1, (struct epoll_event *)canonical->args[3],
				normalized_event);
	s->ref_types[0]         = BUFFER_TYPE(NORMALIZED_EPOLL_EVENT_SIZE,
	                                      1, s->buf_refs);
	s->buf_refs[0]          = (struct buffer_reference)
	                          {.offset = NORMALIZED_EPOLL_EVENT_DATA_OFFSET,
	                           .type = &s->ref_types[1]};
	/* (struct epoll_event).data buffer is ignored; it may contain pointers
	   and other data that varies between variants */
	s->ref_types[1]         = IGNORE_TYPE();
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	/* Handle different operations -- note that we need to undo anything
	   done here if the actual call on the leader fails in the post-call
	   handler! */
	switch(op) {
		case EPOLL_CTL_ADD: {
			/* Store original (epfd, fd, events) --> data mapping,
			   to be returned upon epoll_wait(). */
			struct epoll_data_info event_info = 
				(struct epoll_data_info) {
					.epfd = epfd,
					.fd = fd,
					.data = *event
				};
			append_epoll_data_info(env, event_info);
			s->custom_event.events = event->events;
			s->custom_event.data.fd = fd;
			actual->args[3] = (long)&s->custom_event;
			break;
		}
		case EPOLL_CTL_MOD: {
			struct epoll_data_info *event_info =
				get_epoll_data_info_for(env, epfd, fd, ~0U);
			if(NULL == event_info) {
				return DISPATCH_ERROR;
			}
			s->custom_event.events = event_info->data.events;
			s->custom_event.data.fd = fd;
			actual->args[3] = (long)&s->custom_event;
			break;
		}
	}

	/* File descriptor remapping */
	s->epfd_di = get_di(0);
	s->fd_di = get_di(2);
	remap_fd(s->epfd_di, 0);
	remap_fd(s->fd_di, 2);

	return DISPATCH_LEADER | DISPATCH_CHECKED | DISPATCH_NEEDS_REPLICATION;
}

SYSCALL_EXIT_PROT(epoll_ctl)
{
	struct scratch {
		struct type ref_types[2];
		struct buffer_reference buf_refs[1];
		struct descriptor_info *epfd_di;
		struct descriptor_info *fd_di;
		struct epoll_event custom_event;
	};
	struct scratch *s = (struct scratch *)*scratch;
	int epfd = canonical->args[0];
	int op = canonical->args[1];
	int fd = canonical->args[2];
	char *normalized_event = (char *)canonical->args[3];

	struct epoll_data_info *event_info = 
		get_epoll_data_info_for(env, epfd, fd, ~0U);

	switch(op) {
		case EPOLL_CTL_ADD: {
			if(0 > actual->ret) {
				if(NULL != event_info) {
					remove_epoll_data_info(env, event_info);
				}
			} else {
				if(NULL == event_info) {
					post_call_error();
				}
			}
			break;
		}
		case EPOLL_CTL_MOD: {
			if(0 > actual->ret) {
				/* This is currently unhandled since we cannot 
				   restore the previous state correctly. (Would 
				   need to save in entry-handler.) */
				post_call_error();
			}
			break;
		}
		case EPOLL_CTL_DEL: {
			if(0 == actual->ret) {
				if(NULL == event_info) {
					post_call_error();
				}
				remove_epoll_data_info(env, event_info);
			}
			break;
		}
	}

	free_scratch();
}


/* ************************************************************************** * 
 * epoll_wait                                                                 *
 *                                                                            *
 * int epoll_wait(int epfd, struct epoll_event *events,                       *
 *                int maxevents, int timeout);                                *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(epoll_wait)
{
	// Forward to epoll_pwait
	canonical->no = SYSCALL_epoll_pwait_CANONICAL;
	canonical->args[4] = 0;
	return SYSCALL_ENTER(epoll_pwait)(env, handler, actual, canonical, 
	                                  scratch);
}


/* ************************************************************************** *
 * epoll_pwait                                                                *
 *     int epoll_pwait(int epfd, struct epoll_event *events,                  *
 *                    int maxevents, int timeout,                             *
 *                    const sigset_t *sigmask);                               *
 * ************************************************************************** */
/* See epoll_create documentation above to see how we handle these calls. */

SYSCALL_ENTER_PROT(epoll_pwait)
{
	int maxevents = actual->args[2];
	if(maxevents <= 0) {
		return DISPATCH_ERROR;
	}

	struct descriptor_info *di = get_di(0);
	alloc_scratch(2 * sizeof(struct type)
	              + maxevents * NORMALIZED_EPOLL_EVENT_SIZE);
	struct type *epoll_events_type = (struct type *)*scratch;
	struct type *sigset_type = ((struct type *)*scratch) + 1;
	char *normalized_events = (char *)(((struct type*)*scratch) + 2);

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(di, 0); // only dispatched on leader, will remap there

	canonical->arg_types[1] = POINTER_TYPE(epoll_events_type);
	// The epoll_event buffer will get normalized in post call handler if it
	// needs to be replicated across architectures that have differently-
	// sized struct epoll_event sizes. This may change the size of this
	// buffer.
	*epoll_events_type = BUFFER_TYPE(maxevents 
	                                 * NORMALIZED_EPOLL_EVENT_SIZE);
	canonical->args[1] = (long)normalized_events;
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->arg_types[4] = POINTER_TYPE(sigset_type);
	*sigset_type            = IMMEDIATE_TYPE(unsigned long);

	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	// Just in case we ever implement non-leader dispatch types for epolls.
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_POST_CALL_PROT(epoll_pwait)
{
	if(0 > actual->ret || !(dispatch & DISPATCH_NEEDS_REPLICATION)) {
		return;
	}
	struct type *epoll_events_type = (struct type *)*scratch;
	char *normalized_events = (char *)canonical->args[1];
	size_t sz = 0;
	sz = (long)normalize_epoll_event_structs_into(
				actual->ret,
				(struct epoll_event *)actual->args[1],
				normalized_events);
	epoll_events_type->buffer.length = sz;
}

SYSCALL_EXIT_PROT(epoll_pwait)
{
	/* epoll_wait returns the `struct epoll_event` that was previously
	   registered with `epoll_ctl`.
	   
	   Here, we return exactly the previously registered 
	   `struct epoll_event` to make sure `epoll_wait` behaves correctly and
	   as expected by the variant. */
	
	if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
		// Just in case we ever implement this dispatch type for epolls.
		return;
	}

	int epfd = canonical->args[0];
	int maxevents = actual->args[2];
	int n_events = actual->ret;
	char *normalized_events = (char *)canonical->args[1];  
	struct epoll_event *events = (struct epoll_event *)actual->args[1];

	if(0 > n_events) {
		return;
	} else if(n_events > maxevents) {
		post_call_error();
	}

	denormalize_epoll_event_structs_into(n_events, normalized_events, 
	                                     events);

	struct epoll_event *custom_event = NULL;
	struct epoll_data_info *own_event = NULL;
	for(int i = 0; i < n_events; i++) {
		custom_event = &events[i];
		own_event = get_epoll_data_info_for(
			env, epfd, custom_event->data.fd, custom_event->events);
		if(NULL == own_event) {
			post_call_error();
		}
		memcpy(&events[i].data, &own_event->data.data, 
		       sizeof(own_event->data.data));
	}
}


/* ************************************************************************** * 
 * sendfile                                                                   *
 *                                                                            *
 * ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(sendfile)
{
	struct descriptor_info *out_fd_di = get_di(0);
	struct descriptor_info *in_fd_di = get_di(1);

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(out_fd_di, 0);
	canonical->arg_types[1] = DESCRIPTOR_TYPE();
	remap_fd(in_fd_di, 1);

	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	if(out_fd_di->flags & DI_OPENED_ON_LEADER ||
	   in_fd_di->flags & DI_OPENED_ON_LEADER) {
		return DISPATCH_CHECKED | DISPATCH_LEADER 
		       | DISPATCH_NEEDS_REPLICATION;
	}

	return DISPATCH_CHECKED | DISPATCH_EVERYONE;
}


/* ************************************************************************** *
 * getgroups                                                                  * 
 *                                                                            *
 * int getgroups(int size, gid_t list[]);                                     *
 * ************************************************************************** */ 

SYSCALL_ENTER_PROT(getgroups)
{
	int size = actual->args[0];
	if(0 > size) {
		return DISPATCH_ERROR;
	}

	alloc_scratch(sizeof(struct type));
	struct type *ref_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(ref_type);
	*ref_type               = BUFFER_TYPE(sizeof(gid_t) * size);
	return DISPATCH_CHECKED | DISPATCH_EVERYONE;
}


/* ************************************************************************** *
 * setgroups                                                                  * 
 *                                                                            *
 * int setgroups(size_t size, const gid_t *list);                             *
 * ************************************************************************** */ 

SYSCALL_ENTER_PROT(setgroups)
{
	size_t size = actual->args[0];
	alloc_scratch(sizeof(struct type));
	struct type *ref_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(size_t);
	canonical->arg_types[1] = POINTER_TYPE(ref_type);
	*ref_type               = BUFFER_TYPE(sizeof(gid_t) * size);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY;
	return DISPATCH_CHECKED | DISPATCH_EVERYONE;
}


/* ************************************************************************** *
 * getsockopt                                                                 * 
 *                                                                            *
 * int getsockopt(int sockfd, int level, int optname,                         *
 *                void *restrict optval, socklen_t *restrict optlen);         * 
 * ************************************************************************** */ 

SYSCALL_ENTER_PROT(getsockopt)
{
	socklen_t *optlen = (socklen_t *)canonical->args[4];
	alloc_scratch(2 * sizeof(struct type));
	struct type *optval_type = (struct type *)*scratch;
	struct type *optlen_type = (struct type *)(*scratch 
	                                           + sizeof(struct type));
	struct descriptor_info *di = get_di(0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(di, 0);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = POINTER_TYPE(optval_type);
	*optval_type            = BUFFER_TYPE(*optlen);
	canonical->arg_flags[3] = ARG_FLAG_REPLICATE | ARG_FLAG_WRITE_ONLY;
	canonical->arg_types[4] = POINTER_TYPE(optlen_type);
	*optlen_type            = BUFFER_TYPE(sizeof(socklen_t));
	canonical->arg_flags[4] = ARG_FLAG_REPLICATE;
	canonical->ret_type     = IMMEDIATE_TYPE(long);
	canonical->ret_flags    = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

/* ************************************************************************** *
 * setsockopt                                                                 * 
 *                                                                            *
 * int setsockopt(int sockfd, int level, int optname,                         *
 *                const void *optval, socklen_t optlen);                      * 
 * ************************************************************************** */ 

SYSCALL_ENTER_PROT(setsockopt)
{
	socklen_t optlen = (socklen_t)canonical->args[4];
	alloc_scratch(sizeof(struct type));
	struct type *optval_type = (struct type *)*scratch;
	struct descriptor_info *di = get_di(0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(di, 0);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = POINTER_TYPE(optval_type);
	*optval_type            = BUFFER_TYPE(optlen);
	canonical->arg_types[4] = IMMEDIATE_TYPE(socklen_t);
	canonical->ret_type     = IMMEDIATE_TYPE(long);
	canonical->ret_flags    = ARG_FLAG_REPLICATE;

	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}


/* ************************************************************************** *
 * accept4                                                                    *
 *                                                                            *
 *  int accept4(int sockfd, struct sockaddr *restrict addr,                   *
 *              socklen_t *restrict addrlen, int flags);                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(accept4)
{
	alloc_scratch(2 * sizeof(struct type));
	struct type *addr_type = (struct type *)*scratch;
	struct type *addrlen_type = (struct type *)(*scratch 
	                                            + sizeof(struct type));
	socklen_t *addrlen = (socklen_t *)canonical->args[2];
	if(0 >= *addrlen) {
		return DISPATCH_ERROR;
	}
	struct descriptor_info *di = get_di(0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(di, 0);
	canonical->arg_types[1] = POINTER_TYPE(addr_type);
	*addr_type              = BUFFER_TYPE(*addrlen);
	canonical->arg_flags[1] = ARG_FLAG_REPLICATE | ARG_FLAG_WRITE_ONLY;
	canonical->arg_types[2] = POINTER_TYPE(addrlen_type);
	*addrlen_type           = BUFFER_TYPE(sizeof(socklen_t));
	canonical->arg_flags[2] = ARG_FLAG_REPLICATE;
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->ret_type     = IMMEDIATE_TYPE(long);
	canonical->ret_flags    = ARG_FLAG_REPLICATE;

	return DISPATCH_CHECKED | DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION;
}


/* ************************************************************************** *
 * rt_sigprocmask                                                             *
 *                                                                            *
 * int syscall(SYS_rt_sigprocmask, int how, const kernel_sigset_t *set,       *
 *             kernel_sigset_t *oldset, size_t sigsetsize);                   *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(rt_sigprocmask)
{
	alloc_scratch(sizeof(struct type) * 2);
	struct type *set_type = (struct type*)*scratch;
	struct type *oldset_type = ((struct type*)*scratch) + 1;
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(set_type);
	*set_type = IMMEDIATE_TYPE(unsigned long);
	canonical->arg_types[2] = POINTER_TYPE(oldset_type);
	*oldset_type = IGNORE_TYPE(); // IMMEDIATE_TYPE(unsigned long);
	canonical->arg_types[3] = IMMEDIATE_TYPE(size_t);
	canonical->args[3] = (canonical->args[3] == 0 ? 0 : 1);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}


/* ************************************************************************** *
 * getrlimit                                                                  *
 *                                                                            *
 * int getrlimit(int resource, struct rlimit *rlim);                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(getrlimit)
{
	alloc_scratch(sizeof(struct type));
	struct type *rlim_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(rlim_type);
	*rlim_type              = BUFFER_TYPE(sizeof(struct rlimit));
	// TODO currently assumes struct rlimits are the same size across
	// architectures, with identical offests
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY;
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

/* ************************************************************************** *
 * setrlimit                                                                  *
 *                                                                            *
 * int getrlimit(int resource, const struct rlimit *rlim);                    *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(setrlimit)
{
	alloc_scratch(sizeof(struct type));
	struct type *rlim_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(rlim_type);
	*rlim_type              = BUFFER_TYPE(sizeof(struct rlimit));
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

/* ************************************************************************** *
 * getsockname / getpeername                                                  * 
 * int getsockname(int sockfd, struct sockaddr *restrict addr,                *
 *                 socklen_t *restrict addrlen);                              *
 * int getpeername(int sockfd, struct sockaddr *restrict addr,                *
 *                 socklen_t *restrict addrlen);                              *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(getsockname) 
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	alloc_scratch(2*sizeof(struct type));
	struct type *sockaddr_type = (struct type *)*scratch;
	struct type *socklen_type = ((struct type *)*scratch) + 1;
	if(NULL == (socklen_t *)actual->args[2]
	   || *(socklen_t *)actual->args[2] != sizeof(struct sockaddr)) {
		/* A little restrictive. Anything bigger would be fine, but
		   unexpected and could indicate something else going wrong. */
		return DISPATCH_ERROR;
	}

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(sockaddr_type);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	*sockaddr_type = BUFFER_TYPE(sizeof(struct sockaddr));
	canonical->arg_types[2] = POINTER_TYPE(socklen_type);
	canonical->arg_flags[2] = ARG_FLAG_REPLICATE;
	*socklen_type = IMMEDIATE_TYPE(socklen_t);
	canonical->ret_type = IMMEDIATE_TYPE(int);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}
