#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/sched.h>  // for clone()
#include <sched.h> // for clone()
#include <limits.h>

#include "util.h"
#include "handlers.h"
#include "handler_table.h"
#include "serialization.h"
#include "handler_data_types.h"
#include "environment.h"
#include "monitor.h"
#include "globals.h"
#include "exchanges.h"

#include "handler_table_definitions.h"
#include "handlers_support.h"

// These variables hold the scratch values between system call entry and exit
// handlers
__attribute__((section("unprotected_data")))
char handler_scratch_buffer[HANDLER_SCRATCH_BUFFER_SZ] = {};
void *next_preallocated = handler_scratch_buffer;

struct syscall_handler const *get_handler(long no)
{
#if VERBOSITY >= 2
	static size_t leaked = 0;
	if(leaked < (char*)next_preallocated - handler_scratch_buffer) {
		SAFE_WARNF("Previous system call handler leaked %ld bytes of "
		           "scratch memory.\n",
		           (char *)next_preallocated - handler_scratch_buffer
			   - leaked);
		leaked = (char*)next_preallocated - handler_scratch_buffer;
	}
#endif
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

SYSCALL_EXIT_PROT(default_creates_fd)
{
	struct descriptor_info *di;
	enum descriptor_type type;
	if(0 > actual->ret) {
		return 0;
	}
#if VERBOSITY >= 4
	SAFE_LOGF("%s adding descriptor.\n", handler->name);
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
		case SYSCALL_socketpair_CANONICAL:
			type = SOCKET_DESCRIPTOR;
			break;
		case SYSCALL_epoll_create_CANONICAL:
		case SYSCALL_epoll_create1_CANONICAL:
			type = EPOLL_DESCRIPTOR;
			break;
	}
	di = env_add_local_descriptor(env, local_fd, flags, type);
	actual->ret = env_canonical_fd_for(env, di);
	return 0;
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
 * int access(const char *pathname, int mode);                                *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(access)
{
	// Redirect to facessat handlers
	canonical->args[2] = canonical->args[1];
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = AT_FDCWD;
	canonical->no = SYSCALL_faccessat_CANONICAL;
	return redirect_enter(faccessat);
}

SYSCALL_EXIT_PROT(access)
{
	return redirect_exit(faccessat);
}


/* ************************************************************************** *
 * faccessat                                                                  *
 * int faccessat(int dirfd, const char *pathname, int mode);                  *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(faccessat)
{
	int dispatch = get_dispatch_by_path((const char *)canonical->args[1]);
	alloc_scratch(sizeof(struct type)
	              + MAX_PATH_LENGTH);
	if(AT_FDCWD != (int)canonical->args[0]) {
		struct descriptor_info *di = get_di(0);
		remap_fd(di, 0);
	}
	struct type *string_type = (struct type *)*scratch;
	char *fixed_path_buf = (char *)(*scratch + sizeof(struct type));
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(string_type);
	*string_type            = STRING_TYPE();
	fix_path_arg(env, 1, fixed_path_buf);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
		canonical->ret_flags = ARG_FLAG_REPLICATE;
	}
	return dispatch;
}

SYSCALL_EXIT_PROT(faccessat)
{
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * open                                                                       *
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

SYSCALL_EXIT_PROT(open)
{
	return redirect_exit(openat);
}


/* ************************************************************************** *
 * openat                                                                     *
 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(openat)
{
	struct descriptor_info *di = NULL;
	if(AT_FDCWD != (int)canonical->args[0]) {
		get_di(0);
		remap_fd(di, 0);
	}

	alloc_scratch(sizeof(struct type)
	              + MAX_PATH_LENGTH);
	struct type *string_type = (struct type *)*scratch;
	char *fixed_path_buf = (char *)(*scratch + sizeof(struct type));

	int flags = canonical->args[2];

	/* Move arguments to canonical form: openat */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = STRING_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(string_type);
	           *string_type = STRING_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	// Some flags are encoded differently between x86 ARM; do not cross-check
	// those flags for now
	canonical->args[2] &= ~(O_DIRECTORY | O_NOFOLLOW | O_DIRECT | O_LARGEFILE);
	if(flags & (O_CREAT)) { // O_TMPFILE
		canonical->arg_types[3] = IMMEDIATE_TYPE(mode_t);
	} else {
		canonical->arg_types[3] = IGNORE_TYPE();
	}
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	int dispatch = get_dispatch_by_path((const char *)canonical->args[1]);
	fix_path_arg(env, 1, fixed_path_buf);
	
	return dispatch;

}

SYSCALL_EXIT_PROT(openat)
{
	free_scratch();
	write_back_canonical_return();
	return redirect_exit(default_creates_fd);
}


/* ************************************************************************** *
 * close                                                                      *
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
	/* We must purge the epoll information before close() exits, because
	   afterwards the file descriptor is meaningless and can't be used
	   for epoll_ctl. Hence, we assume the close will suceed. */
	if(di->flags & DI_WATCHED_BY_EPOLL) {
		SAFE_NZ_TRY(
			purge_epoll_data_fd(env, env_canonical_fd_for(env, di))
		); 
	}
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(close)
{
	struct descriptor_info *di = (struct descriptor_info *)*scratch;
	write_back_canonical_return();
	if(0 == (int)actual->ret) {
#if VERBOSITY >= 4
		SAFE_LOGF("close removing descriptor.%s", "\n");
#endif
		SAFE_NZ_TRY(env_del_descriptor(env, di));
	}
	return 0;
}


/* ************************************************************************** *
 * mmap                                                                       * 
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

	/* On some architectures, malloc may issue an anonymous mmap call where
	   it is a brk call on another. To avoid false positive divergences,
	   we leave this system call unchecked. */
	return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
}

/* ************************************************************************** *
 * mprotect                                                                   *
 * int mprotect(void *addr, size_t len, int prot)                             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(mprotect)
{
	canonical->args[0] = (0 == canonical->args[0] ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(uint64_t);
	canonical->arg_types[1] = IMMEDIATE_TYPE(uint64_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(uint32_t);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

/* ************************************************************************** *
 * madvise                                                                    *
 * int madvise(void *addr, size_t length, int advice);                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(madvise)
{
	// Skip checking madvise for now; seems to lead to benign divergences
	return DISPATCH_EVERYONE | DISPATCH_UNCHECKED;
	canonical->args[0] = (0 == canonical->args[0] ? 0 : 1);
	/*
	canonical->arg_types[0] = IMMEDIATE_TYPE(void *);
	// Ignore length argument for now since memory may contain arch-specific
	// structures of different sizes.
	// canonical->arg_types[1] = IMMEDIATE_TYPE(size_t);
	canonical->arg_types[1] = IGNORE_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
	*/
}

/* ************************************************************************** *
 * munmap                                                                     * 
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

	/* Black magic ... wait a little so more bytes are available for
	   reading, instead of immediately returning without any data just
	   for the target program to call us again. */
	if(0 < monitor.conf.socket_read_usleep 
	   && di->type == SOCKET_DESCRIPTOR
	   && is_open_locally(env, di)) {
		usleep(monitor.conf.socket_read_usleep);
	}

	/* Argument 1*/
	canonical->arg_types[0] = DESCRIPTOR_TYPE();

	/* Argument 2 */
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
		   ref_types[0] = BUFFER_TYPE((size_t)canonical->args[2]);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;

	/* Argument 3 */
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
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * pread                                                                      * 
 * ssize_t pread(int fd, void *buf, size_t count, off_t offset);              *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(pread)
{
	/* Identical to read except for additional offset argument, hence
	   we redirect to read handlers. */
	int read_dispatch = redirect_enter(read);

	canonical->arg_types[3] = IMMEDIATE_TYPE(off_t);

	return read_dispatch;
}

SYSCALL_EXIT_PROT(pread)
{
	return redirect_exit(read);
}


/* ************************************************************************** *
 * readv                                                                      * 
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
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * write                                                                      * 
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
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * pwrite                                                                     * 
 * ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(pwrite)
{
	/* Identical to write except for additional offset argument, hence
	   we redirect to write handlers. */
	int write_dispatch = redirect_enter(write);

	canonical->arg_types[3] = IMMEDIATE_TYPE(off_t);

	return write_dispatch;
}

SYSCALL_EXIT_PROT(pwrite)
{
	return redirect_exit(write);
}


/* ************************************************************************** *
 * writev                                                                     * 
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
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * stat                                                                       * 
 * int stat(const char *restrict pathname,                                    *
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
	return redirect_enter(fstatat);
}

SYSCALL_POST_CALL_PROT(stat)
{
	return redirect_post_call(fstatat);
}

SYSCALL_EXIT_PROT(stat)
{
	redirect_exit(fstatat);
	actual->args[0] = actual->args[1];
	actual->args[1] = actual->args[2];
	actual->args[1] = actual->args[2];
	return 0;
}


/* ************************************************************************** *
 * fstat                                                                      * 
 * int fstat(int fildes, struct stat *buf);                                   * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fstat)
{
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);

	int dispatch = 0; 
	if(di->flags & DI_UNCHECKED && di->flags & DI_OPENED_LOCALLY) {
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
		goto done;
	}
	actual->ret = canonical->ret;
	char *normalized_stat = (char *)canonical->args[1];
	denormalize_stat_struct_into(normalized_stat,
	                             (struct stat *)actual->args[1]);
	if(NULL != normalized_stat) {
		free(normalized_stat);
	}
done:
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * fstatat                                                                    * 
 * int fstatat(int fd, const char *restrict path,                             *
 *             struct stat *restrict buf, int flag);                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fstatat)
{
	struct descriptor_info *di = NULL;
	if(AT_FDCWD != (int)actual->args[0]) {
		get_di(0);
		remap_fd(di, 0);
	}
	alloc_scratch(2 * sizeof(struct type)
	              + MAX_PATH_LENGTH);
	struct type *stat_buf_type = (struct type *)*scratch;
	struct type *str_type = ((struct type *)*scratch) + 1;
	char *fixed_path_buf = (char *)(*scratch + 2*sizeof(struct type));

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
	fix_path_arg(env, 1, fixed_path_buf);

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
		actual->ret = canonical->ret;
	}
	if(NULL != normalized_stat) {
		free(normalized_stat);
	}
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * time                                                                       * 
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
	return 0;
}


/* ************************************************************************** *
 * gettimeofday                                                               * 
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
	actual->ret = canonical->ret;
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * clock_gettime                                                              *
 * int clock_gettime(clockid_t clockid, struct timespec *tp);                 *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(clock_gettime)
{
	alloc_scratch(sizeof(struct type));
	struct type *buf_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(long);
	canonical->arg_types[1] = POINTER_TYPE(buf_type);
	*buf_type               = BUFFER_TYPE(sizeof(struct timespec));
	canonical->arg_flags[1] = ARG_FLAG_REPLICATE | ARG_FLAG_WRITE_ONLY;
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return DISPATCH_CHECKED | DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION;
}

SYSCALL_EXIT_PROT(clock_gettime)
{
	free_scratch();
	write_back_canonical_return();
	return 0;
}


/* ************************************************************************** *
 * dup2                                                                       * 
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
	
	return redirect_enter(dup3);
}

SYSCALL_EXIT_PROT(dup2)
{
	if(dispatch & DISPATCH_SKIP) {
		return 0;
	}
	return redirect_exit(dup3);
}


/* ************************************************************************** *
 * dup3                                                                       * 
 * int dup3(int oldfd, int newfd, int flags);                                 *
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
	write_back_canonical_return();

	if(0 > actual->ret) {
		goto ret;
	}

	struct descriptor_info **di = (struct descriptor_info **)*scratch;

	if(NULL != di[1]) {
		/* newfd will override a fd previously opened by the variant. 
		   old local fd was closed by a successful dup2 call. */
#if VERBOSITY >= 4
		SAFE_LOGF("dup3 removing descriptor.%s", "\n");
#endif
		env_del_descriptor(env, di[1]);
	}

	int local_fd = -1;
	if(is_open_locally(env, di[0])) {
		local_fd = actual->ret;
	}
#if VERBOSITY >= 4
	SAFE_LOGF("dup3 adding descriptor.%s", "\n");
#endif
	Z_TRY_EXCEPT(env_add_descriptor(env, local_fd, newfd, di[0]->flags,
	                                di[0]->type),
	             newfd = -1);
	
	actual->ret = newfd;

ret:
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * lseek                                                                      * 
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

SYSCALL_EXIT_PROT(lseek)
{
	write_back_canonical_return();
	return 0;
}


/* ************************************************************************** *
 * socket                                                                     *
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

SYSCALL_EXIT_PROT(socket)
{
	write_back_canonical_return();
	return redirect_exit(default_creates_fd);
}


/* ************************************************************************** *
 * socketpair                                                                 *
 * int socketpair(int domain, int type, int protocol, int sv[2]);             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(socketpair)
{
	alloc_scratch(sizeof(struct type));
	struct type *buffer_type = (struct type *)*scratch;
	int domain = actual->args[0];
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = POINTER_TYPE(buffer_type);
	*buffer_type            = BUFFER_TYPE(sizeof(int) * 2);
	canonical->arg_flags[3] = ARG_FLAG_WRITE_ONLY;
	if(domain == AF_UNIX) {
		return DISPATCH_EVERYONE | DISPATCH_CHECKED;
	} else {
		canonical->arg_flags[3] |= ARG_FLAG_REPLICATE;
		canonical->ret_flags = ARG_FLAG_REPLICATE;
		return DISPATCH_LEADER | DISPATCH_CHECKED
			| DISPATCH_NEEDS_REPLICATION;
	}
	// Unreachable.
}

SYSCALL_EXIT_PROT(socketpair)
{
	struct descriptor_info *di[2];
	if(0 > actual->ret) {
		goto done;
	}

#if VERBOSITY >= 4
	SAFE_LOGF("%s adding descriptor.\n", handler->name);
#endif

	int flags = 0;
	int local_fd[2] = {-1, -1};
	int *actual_fds = (int *)actual->args[3];
	if(dispatch & DISPATCH_EVERYONE) {
		flags |= DI_OPENED_LOCALLY;
		local_fd[0] = actual_fds[0];
		local_fd[1] = actual_fds[1];
	} else if(env->is_leader) {
		flags |= DI_OPENED_ON_LEADER;
		local_fd[0] = actual_fds[0];
		local_fd[1] = actual_fds[1];
	} else {
		flags = DI_OPENED_ON_LEADER;
	}
	if(dispatch & DISPATCH_UNCHECKED) {
		flags |= DI_UNCHECKED;
	}
	di[0] = env_add_local_descriptor(env, local_fd[0], flags, 
	                                 SOCKET_DESCRIPTOR);
	di[1] = env_add_local_descriptor(env, local_fd[1], flags, 
	                                 SOCKET_DESCRIPTOR);

	actual_fds[0] = env_canonical_fd_for(env, di[0]);
	actual_fds[1] = env_canonical_fd_for(env, di[1]);

done:
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * epoll_create                                                               *
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
	return redirect_enter(epoll_create1);
}

SYSCALL_EXIT_PROT(epoll_create)
{
	return redirect_exit(epoll_create1);
}


/* ************************************************************************** *
 * epoll_create1                                                              *
 * int epoll_create(int flags);                                               *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(epoll_create1)
{
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(epoll_create1)
{
	write_back_canonical_return();
	return redirect_exit(default_creates_fd);
}


/* ************************************************************************** * 
 * epoll_ctl                                                                  *
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
					.event = *event
				};
			SAFE_NZ_TRY_EXCEPT(
				append_epoll_data_info(env, event_info),
				return DISPATCH_ERROR);
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
			s->custom_event.events = event_info->event.events;
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
	write_back_canonical_return();
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
			struct descriptor_info *di = 
				env_get_canonical_descriptor_info(env, fd);
			if(0 > actual->ret) {
				if(NULL != event_info) {
					remove_epoll_data_info(env, event_info);
				}
			} else {
				if(NULL == event_info) {
					SAFE_WARN("Cannot find event_info "
					          "to add.\n");
					post_call_error();
				}
				if(NULL != di) {
					di->flags |= DI_WATCHED_BY_EPOLL;
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
					SAFE_WARN("Cannot find event_info to "
					          "delete.\n");
					post_call_error();
				}
				remove_epoll_data_info(env, event_info);
			}
			break;
		}
	}
	free_scratch();
	return 0;
}


/* ************************************************************************** * 
 * epoll_wait                                                                 *
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
 * int epoll_pwait(int epfd, struct epoll_event *events,                  *
 *                int maxevents, int timeout,                             *
 *                const sigset_t *sigmask);                               *
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
		goto done;
	}

	write_back_canonical_return();

	int epfd = canonical->args[0];
	int maxevents = actual->args[2];
	int n_events = actual->ret;
	char *normalized_events = (char *)canonical->args[1];  
	struct epoll_event *events = (struct epoll_event *)actual->args[1];

	if(0 > n_events) {
		goto done;
	} else if(n_events > maxevents) {
		post_call_error();
	}

	denormalize_epoll_event_structs_into(n_events, normalized_events, 
	                                     events);

	struct epoll_event *custom_event = NULL;
	struct epoll_data_info *own_event = NULL;
	size_t j = 0;
	for(int i = 0; i < n_events; i++) {
		custom_event = &events[i];
		own_event = get_epoll_data_info_for(
			env, epfd, custom_event->data.fd, custom_event->events);
		if(NULL == own_event) {
			SAFE_WARNF("No matching epoll event data structure "
			           "found for epfd %d, fd %d (index %d)\n",
				   epfd, custom_event->data.fd, i);
			//post_call_error();
			continue;
		}
		memcpy(&events[j].data, &own_event->event.data, 
		       sizeof(own_event->event.data));
		j++;
	}

	actual->ret = j;

done:
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * eventfd2                                                                   *
 * int eventfd2(unsigned int initval, int flags);                             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(eventfd2)
{
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(eventfd2)
{
	return redirect_exit(default_creates_fd);
}


/* ************************************************************************** * 
 * sendfile                                                                   *
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

SYSCALL_EXIT_PROT(sendfile)
{
	write_back_canonical_return();
	return 0;
}


/* ************************************************************************** *
 * getgroups                                                                  * 
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

SYSCALL_EXIT_PROT(getgroups)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * setgroups                                                                  * 
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

SYSCALL_EXIT_PROT(setgroups)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * getsockopt                                                                 * 
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

SYSCALL_EXIT_PROT(getsockopt)
{
	free_scratch();
	write_back_canonical_return();
	return 0;
}


/* ************************************************************************** *
 * setsockopt                                                                 * 
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

SYSCALL_EXIT_PROT(setsockopt)
{
	free_scratch();
	write_back_canonical_return();
	return 0;
}


/* ************************************************************************** *
 * fcntl                                                                      *
 * int fcntl(int fd, int cmd, ... );                                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fcntl) { 
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	int cmd = actual->args[1];
	int dispatch = dispatch_leader_if_needed(di, DISPATCH_CHECKED);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(int);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	switch(cmd) {
		case F_GETFD:
		case F_GETFL:
		case F_GETOWN:
		case F_GETPIPE_SZ:
			break;
		case F_SETFD:
		case F_SETFL:
		case F_SETPIPE_SZ:
			canonical->arg_types[2] = IMMEDIATE_TYPE(int);
			break;
		case F_SETOWN: {
			if((dispatch & DISPATCH_EVERYONE) || 
			   (dispatch & DISPATCH_LEADER && env->is_leader)) {
				struct pid_info *pi = get_pid_info(2);
				actual->args[2] = pi->local_pid;
			}
			canonical->arg_types[2] = IMMEDIATE_TYPE(pid_t);
			break;
		}
		default:
			SAFE_WARNF("As of yet unhandled fcntl command: %d.\n",
			           cmd);
			return DISPATCH_ERROR;
	}
	return dispatch;
}

SYSCALL_EXIT_PROT(fcntl) { 
	int cmd = actual->args[1];
	write_back_canonical_return();
	switch(cmd) {
		case F_GETFD:
		case F_GETFL:
		case F_GETPIPE_SZ:
			break;
		case F_GETOWN: {
			struct pid_info *pi;
			if((dispatch & DISPATCH_EVERYONE) || 
			   (dispatch & DISPATCH_LEADER && env->is_leader)) {
				SAFE_Z_TRY_EXCEPT(
					pi =env_get_local_pid_info(env, 
					                           actual->ret),
					return 1);
				actual->ret = env_canonical_pid_for(env, pi);
			}
			break;
		}
		case F_SETFD:
		case F_SETFL:
		case F_SETOWN:
		case F_SETPIPE_SZ:
			break;
		default:
			// As of yet unhandled fcntl command.
			return 1;
	}
	return 0;
 }


/* ************************************************************************** *
 * connect                                                                    *
 * int connect(int sockfd, const struct sockaddr *addr,                       *
 *             socklen_t addrlen);                                            *
 * TODO!                                                                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(connect) { return redirect_enter(default_arg1_fd); }
SYSCALL_EXIT_PROT(connect) { write_back_canonical_return(); return 0; }


/* ************************************************************************** *
 * bind                                                                       *
 * int bind(int sockfd, const struct sockaddr *addr,                          * 
 *          socklen_t addrlen);                                               * 
 * TODO!                                                                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(bind) { return redirect_enter(default_arg1_fd); }
SYSCALL_EXIT_PROT(bind) { write_back_canonical_return(); return 0; }


/* ************************************************************************** *
 * listen                                                                     *
 * int listen(int sockfd, int backlog);                                       * 
 * TODO!                                                                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(listen) { return redirect_enter(default_arg1_fd); }
SYSCALL_EXIT_PROT(listen) { write_back_canonical_return(); return 0; }


/* ************************************************************************** *
 * accept                                                                     *
 * int accept(int sockfd, struct sockaddr *restrict addr,                     *
 *            socklen_t *restrict addrlen);                                   *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(accept)
{
	canonical->no = SYSCALL_accept4_CANONICAL;
	canonical->args[3] = 0;
	return redirect_enter(accept4);
}

SYSCALL_EXIT_PROT(accept)
{
	return redirect_exit(accept4);
}


/* ************************************************************************** *
 * accept4                                                                    *
 * int accept4(int sockfd, struct sockaddr *restrict addr,                    *
 *             socklen_t *restrict addrlen, int flags);                       *
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

SYSCALL_EXIT_PROT(accept4)
{
	free_scratch();
	write_back_canonical_return();
	return redirect_exit(default_creates_fd);
}


/* ************************************************************************** *
 * shutdown                                                                   *
 * int shutdown(int sockfd, int how);                                         *
 * TODO!                                                                      * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(shutdown) { return redirect_enter(default_arg1_fd); }
SYSCALL_EXIT_PROT(shutdown) { write_back_canonical_return(); return 0; }


/* ************************************************************************** *
 * rt_sigprocmask                                                             *
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

SYSCALL_EXIT_PROT(rt_sigprocmask)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * ioctl                                                                      *
 * int ioctl(int fd, unsigned long request, ...);                             *
 * TODO!                                                                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(ioctl) { return redirect_enter(default_arg1_fd); }
SYSCALL_EXIT_PROT(ioctl) { write_back_canonical_return(); return 0; }


/* ************************************************************************** *
 * recvfrom                                                                   *
 * ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,             *
 *                  struct sockaddr *src_addr, socklen_t *addrlen);           *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(recvfrom) { 
	struct recvfrom_scratch {
		struct type buf_type;
		struct type src_addr_type;
		struct type addrlen_type;
	};
	alloc_scratch(sizeof(struct recvfrom_scratch));
	struct recvfrom_scratch *_scratch = (struct recvfrom_scratch *)*scratch;
	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	size_t len = actual->args[2];
	socklen_t addrlen = 0;
	if(0 != actual->args[5]) {
		addrlen = *(socklen_t *)actual->args[5];
	}
	if(!(di->flags & DI_OPENED_ON_LEADER)) {
		// Do not yet handle recvfrom for local sockets.
		return DISPATCH_ERROR;
	}
	// sockfd
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	// buf
	canonical->arg_types[1] = POINTER_TYPE(&_scratch->buf_type);
	_scratch->buf_type      = BUFFER_TYPE(len);
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	// len
	canonical->arg_types[2] = IMMEDIATE_TYPE(size_t);
	// flags
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	// src_addr
	canonical->arg_types[4] = POINTER_TYPE(&_scratch->src_addr_type);
	_scratch->src_addr_type = BUFFER_TYPE(addrlen);
	// addrlen
	canonical->arg_types[5] = POINTER_TYPE(&_scratch->addrlen_type);
	_scratch->addrlen_type  = BUFFER_TYPE(sizeof(socklen_t));
	canonical->arg_flags[5] = ARG_FLAG_REPLICATE;
	// return
	canonical->ret_type     = IMMEDIATE_TYPE(long);
	canonical->ret_flags    = ARG_FLAG_REPLICATE;
	return DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(recvfrom) { 
	free_scratch();
	write_back_canonical_return(); 
	return 0;
}


/* ************************************************************************** *
 * getrlimit                                                                  *
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

SYSCALL_EXIT_PROT(getrlimit)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * setrlimit                                                                  *
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

SYSCALL_EXIT_PROT(setrlimit)
{
	free_scratch();
	return 0;
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
	   || *(socklen_t *)actual->args[2] < sizeof(struct sockaddr)) {
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

SYSCALL_EXIT_PROT(getsockname)
{
	write_back_canonical_return();
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * sendmsg                                                                    *
 * ssize_t sendmsg(int socket, const struct msghdr *message, int flags);      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(sendmsg)
{
	struct msghdr *msghdr = (struct msghdr *)actual->args[1];

	/* Allocate scratch space to store our type descriptions for the
	   fields inside struct msghdr. We will need a variable amount of space
	   in order to describe the struct iovecs, depending on their count. For
	   the list of iovecs, we will need a buffer_reference type that
	   describes the pointer from the struct msghdr to the list of iovecs.
	   Then, for each iovec, we need a reference type for the buffer it
	   points to, and two types (the pointer to that buffer and the 
	   buffer itself). */
	struct sendmsg_scratch {
		struct type msghdr_type;
		struct buffer_reference msghdr_refs[2];
		struct type msg_iov_ptr_type; // struct iovec * msghdr.msg_iov
		struct type msg_iov_type; // struct iovec (*msghdr.msg_iov)
		struct type msg_control_ptr_type; // void * msghdr.msg_control
		struct type msg_control_type; // void (*msghdr.msg_control)
		struct buffer_reference *addl_refs;
		struct type *addl_types;
	};
	int n_addl_refs = msghdr->msg_iovlen;
	int n_addl_types = 2 * msghdr->msg_iovlen;
	alloc_scratch(sizeof(struct sendmsg_scratch)
		      + sizeof(struct buffer_reference) * n_addl_refs
	              + sizeof(struct type) * n_addl_types);
	struct sendmsg_scratch *_scratch = (struct sendmsg_scratch *)*scratch;
	_scratch->addl_refs = (struct buffer_reference *)
	                      ((char *)_scratch + sizeof(*_scratch));
	_scratch->addl_types = (struct type *) ((char *)_scratch->addl_refs
	                       + sizeof(struct buffer_reference) * n_addl_refs);

	if((msghdr->msg_namelen != 0
	    && msghdr->msg_namelen != sizeof(struct sockaddr))
	   || msghdr->msg_controllen != 0) {
		// Currently not supported.
		return DISPATCH_ERROR;
	}


	/* ----
	   Argument 1
	   ---- */

	struct descriptor_info *di = get_di(0);
	remap_fd(di, 0);
	canonical->arg_types[0] = DESCRIPTOR_TYPE();

	/* ----
	   Argument 2
	   ---- */

	/* Describe struct msghdr * argument:
	   It is a pointer to ... */
	canonical->arg_types[1] = POINTER_TYPE(&_scratch->msghdr_type);
	/* ... a buffer of the size of a struct msghdr ... */
	_scratch->msghdr_type   = BUFFER_TYPE(sizeof(struct msghdr),
	                                      2,
					      _scratch->msghdr_refs);
	/* ... containing tow things:
	   (1) at offset msg_iov, ... */
	_scratch->msghdr_refs[0] = BUFFER_REF(offsetof(struct msghdr, msg_iov),
	                                      &_scratch->msg_iov_ptr_type);
	/* (1) ... a pointer ... */
	_scratch->msg_iov_ptr_type = POINTER_TYPE(&_scratch->msg_iov_type);
	/* (1) ... to a buffer of a dynamic number of struct iovecs ... */
	_scratch->msg_iov_type = BUFFER_TYPE(sizeof(struct iovec) 
	                                     * msghdr->msg_iovlen,
					     msghdr->msg_iovlen,
					     _scratch->addl_refs);
	/* ... and
	   (2) at offset msg_control, ... */
	_scratch->msghdr_refs[1] = BUFFER_REF(offsetof(struct msghdr, 
	                                               msg_control),
	                                      &_scratch->msg_control_ptr_type);
	/* (2) ... a pointer ... */
	_scratch->msg_control_ptr_type = 
		POINTER_TYPE(&_scratch->msg_control_ptr_type);
	/* (2) ... to something we currently do not support and hence ignore */
	_scratch->msg_control_type = IGNORE_TYPE();

	/* Now, for the list of iovecs, each iovec contains references to other
	   buffers: */
	for(int i = 0; i < msghdr->msg_iovlen; i++) {
		const struct iovec * const iov = &msghdr->msg_iov[i];
		_scratch->addl_refs[i] = 
			BUFFER_REF(sizeof(struct iovec) * i
			           + offsetof(struct iovec, iov_base),
				   &_scratch->addl_types[2*i]);
		_scratch->addl_types[2*i] = 
			POINTER_TYPE(&_scratch->addl_types[2*i+1]);
		_scratch->addl_types[2*i+1] =
			BUFFER_TYPE(iov->iov_len);
	}

	/* ----
	   Argument 3
	   ---- */
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);

	canonical->ret_flags = ARG_FLAG_REPLICATE;

	return DISPATCH_CHECKED | DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION;
}

SYSCALL_EXIT_PROT(sendmsg)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * mkdir                                                                      *
 * int mkdir(const char *pathname, mode_t mode);                              *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(mkdir)
{
	/* Redirect to mkdirat handlers. */
	canonical->args[2] = canonical->args[1];
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = AT_FDCWD;
	canonical->no = SYSCALL_mkdirat_CANONICAL;
	return redirect_enter(mkdirat);
}

SYSCALL_EXIT_PROT(mkdir)
{
	return redirect_exit(mkdirat);
}


/* ************************************************************************** *
 * mkdirat                                                                    *
 * int mkdirat(int dirfd, const char *pathname, mode_t mode);                 *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(mkdirat)
{
	alloc_scratch(sizeof(struct type));
	struct type *string_type = (struct type*)*scratch;
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(string_type);
	*string_type            = STRING_TYPE();
	return DISPATCH_CHECKED | DISPATCH_EVERYONE;
}

SYSCALL_EXIT_PROT(mkdirat)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * getpid                                                                     *
 * pid_t getpid(void)                                                         *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(getpid)
{
	SAFE_LZ_TRY_EXCEPT(actual->ret = env_canonical_pid_for(env, env->pid),
	                   return DISPATCH_ERROR);
	return DISPATCH_SKIP;
}


/* ************************************************************************** *
 * getppid                                                                    *
 * pid_t getpid(void)                                                         *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(getppid)
{
	SAFE_LZ_TRY_EXCEPT(actual->ret = env_canonical_pid_for(env, env->ppid),
	                   return DISPATCH_ERROR);
	return DISPATCH_SKIP;
}


/* ************************************************************************** *
 * monmod_fake_fork                                                           *
 * ************************************************************************** */

/* When using libVMA, establishing new connections for spawned child processes
   in the fork() handler causes a deadlock. Since libVMA is a user-space 
   library, it holds some locks when the fork() system call enters. We then
   also try to acquire these locks again by calling into libVMA to initiate our
   child process. 
   
   To avoid this deadlock, we overwrite the fork() function (in vma_redirect.c)
   with our own, that does nothing more than issue this "fake_fork" system call.
   We then call fork() ourselves here, which acquires the locks, issues a
   trusted fork system call, releases the locks and then returs. After all this,
   we now set up the new network connection. */

SYSCALL_ENTER_PROT(monmod_fake_fork)
{
#if USE_LIBVMA == USE_LIBVMA_LOCAL
	alloc_scratch(sizeof(struct communicator));
	struct communicator *child_comm = (struct communicator *)*scratch;
	memset(child_comm, 0, sizeof(*child_comm));
	int dispatch = DISPATCH_SKIP;
	SAFE_NZ_TRY(synchronize(&monitor, FORK_EXCHANGE));
	actual->ret = vmafork();
	if(0 == actual->ret) {  // child
		SAFE_NZ_TRY_EXCEPT(
			monitor_arbitrate_child_comm(&monitor, child_comm),
			return DISPATCH_ERROR);
		canonical->ret = actual->ret;
	}
	if(0 != (redirect_exit(clone))) {  
		// clone exit handler calls free_scratch
		return DISPATCH_ERROR;
	}
	return dispatch;
#else
	/* fake_fork calls should only be issued if libVMA is enabled. They
	   are not needed otherwise. */
	return DISPATCH_ERROR;
#endif
}


/* ************************************************************************** *
 * fork                                                                       *
 * pid_t fork(void)                                                           *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(fork)
{
#if USE_LIBVMA
	/* Fork handlers not supported, use monmod_fake_fork. */
	return DISPATCH_ERROR;
#else
	/* Forward to clone() handler.
	   See glibc sysdeps/unix/sysv/linux/arch-fork.h */
	const int flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD;
	canonical->no = SYSCALL_clone_CANONICAL;
	canonical->args[0] = flags;
	canonical->args[1] = 0;
	canonical->args[2] = (unsigned long)NULL;
	canonical->args[3] = (unsigned long)NULL;  // FIXME
	return redirect_enter(clone);
#endif
}

SYSCALL_EXIT_PROT(fork)
{
	return redirect_exit(clone);
}


/* TODO: There is a newer clone3 interface not implemented in the kernel we 
   use. */

/* ************************************************************************** *
 * clone                                                                      *
 * long clone(unsigned long flags, void *child_stack,                         *
 *            void *ptid, void *ctid,                                         * 
 *            struct pt_regs *regs);                                          * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(clone)
{
#if USE_LIBVMA
	SAFE_WARN("clone() is not supported when using libVMA. fork() is "
	          "only supported using the monmod_fake_fork handler.\n");
	return DISPATCH_ERROR;
#endif
#if !MEASURE_TRACING_OVERHEAD
	alloc_scratch(sizeof(struct communicator));
	struct communicator *child_comm = (struct communicator *)*scratch;

	unsigned long flags = actual->args[0];
	void *child_stack = (void *)actual->args[1];

	/* We currently only support fork()-like semantics for clone. Anything
	   else will be rejected. */
	if(flags & (CLONE_FILES | CLONE_IO | CLONE_FS | CLONE_NEWIPC 
                    | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID
		    | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_PARENT
		    | CLONE_PARENT_SETTID /*| CLONE_PID*/ | CLONE_SIGHAND
		    /*| CLONE_STOPPED*/ | CLONE_SYSVSEM | CLONE_THREAD 
		    | CLONE_VFORK | CLONE_VM ) )
	{
		SAFE_WARNF("Monmod currently only supports fork-like cloning. "
		           "Observed flags: %lx.\n", flags);
		return DISPATCH_ERROR;
	}
	if(0 != child_stack) {
		return DISPATCH_ERROR;
	}

	canonical->arg_types[0] = IMMEDIATE_TYPE(unsigned long);
	canonical->arg_types[1] = IMMEDIATE_TYPE(unsigned long);
	/* Just check newsp for NULL vs non-NULL since stack pointers are going
	   to be different between architectures. */
	canonical->args[1] = (0 == canonical->args[1] ? 0 : 1);

	/* Before we actually fork in to two processes, use the old process to
	   establish a new child monitor. This child monitor will overwrite the
	   default monitor in the child process after the clone() call is
	   completed, and will be thrown away in the parent process. */
	SAFE_NZ_TRY_EXCEPT(monitor_arbitrate_child_comm(&monitor, child_comm),
	                   return DISPATCH_ERROR);

#endif
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(clone)
{
#if !MEASURE_TRACING_OVERHEAD
	struct communicator *child_comm = (struct communicator *)*scratch;
	struct pid_info *pid_info = NULL;
	pid_t child_pid = (pid_t)actual->ret;
	pid_t canonical_child_pid = 0;
	monitor.ancestry++;  // just for log numbers
	if(0 != child_pid) {
		/* In parent: add child PID to environment. */
#if !USE_LIBVMA
		SAFE_NZ_TRY(comm_destroy(child_comm));
#endif
		SAFE_Z_TRY(pid_info = env_add_local_pid_info(env, child_pid));
		SAFE_LZ_TRY(canonical_child_pid = 
		            env_canonical_pid_for(env, pid_info));
		canonical->ret = canonical_child_pid;
		actual->ret = canonical->ret;
	} else {
		/* In child: Use previosly created child_monitor as our new
		   default monitor. */
		monitor.ancestry *= 100; // just for log numbers
		SAFE_NZ_TRY(monitor_child_fix_up(&monitor, child_comm));
	}
	free_scratch();
#endif
	return 0;
}


/* ************************************************************************** *
 * wait                                                                       *
 * pid_t wait(int *wstatus)                                                   *
 * ************************************************************************** */

/* Here is how we handle wait and the associated asynchrony issues.

   1. Child PIDs are remapped to canonical PIDs that are the same between all
      variants. The program is exposed only to those canonical PIDs, and we
      translate to the actual local PID if a system call needs to be executed.
      Each clone/fork/... call that creates a new process thus adds a new entry
      to that mapping.
    2. wait() and waitpid(-1, ...) calls, that could return any child process,
       and hence could return different child processes for different variants
       due to different timing, initially run only on the leader. Then, the
       children execute a waitpid(xxx) specifically for the PID that the 
       leader's wait returned. */

SYSCALL_ENTER_PROT(wait)
{
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = -1;
	return redirect_enter(waitpid);
}

SYSCALL_POST_CALL_PROT(wait)
{
	return redirect_post_call(waitpid);
}

SYSCALL_EXIT_PROT(wait)
{
	return redirect_exit(waitpid);
}


/* ************************************************************************** *
 * waitpid                                                                    *
 * pid_t waitpid(pid_t pid, int *wstatus, int options)                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(waitpid)
{
	struct pid_info *pi = NULL;
	if(-1 != actual->args[0]) {
		pi = get_pid_info(0);
		remap_pid(pi, 0);
	}
	alloc_scratch(sizeof(struct type));
	struct type *buffer_type = (struct type *)*scratch;
	canonical->arg_types[0] = IMMEDIATE_TYPE(pid_t);
	canonical->arg_types[1] = POINTER_TYPE(buffer_type);
	*buffer_type            = BUFFER_TYPE(sizeof(int));
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY;
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(pid_t);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	if(-1 == actual->args[0]) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		       | DISPATCH_NEEDS_REPLICATION;
	}
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_POST_CALL_PROT(waitpid)
{
	if(actual->ret <= 0) {
		return;
	}
	struct pid_info *pid_info = env_get_local_pid_info(env, actual->ret);
	if(NULL == pid_info) {
		return;
	}
	pid_t canonical_pid = env_canonical_pid_for(env, pid_info);
	if(0 > canonical_pid) {
		return;
	}
	actual->ret = canonical_pid;
	canonical->ret = actual->ret;
	/* If this wait returned because the child process no longer exists
	   (terminated), remove it from our list. */
	if(0 != kill(pid_info->local_pid, 0)) {
		if(0 != env_del_pid_info(env, pid_info)) {
			return;
		}
	}
}

SYSCALL_EXIT_PROT(waitpid)
{
	if(-1 != actual->args[0]) {
		goto ret;
	}
	if(!env->is_leader) {
		struct pid_info *pid_info = env_get_pid_info(env, 
		                                             canonical->ret);
		if(NULL != pid_info) {
			return 1;
		}
		/* Leader's wait(-1) returned the received PID in 
		   canonical->ret. Instead of a catch-all wait, we wait for
		   this process specifically in the followers. */
		pid_t retv = waitpid((pid_t)pid_info->local_pid, 
		                     (int *)actual->args[1], 
				     (int)actual->args[2]);
		if(0 >= retv) {
			return 1;
		}
	}
ret:
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * wait3                                                                      *
 * pid_t wait3(int *wstatus, int options, struct rusage *rusage);             *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(wait3)
{
	/* wait3(wstatus, options, rusage) == wait4(-1, wstatus, options, 
	                                            rusage) */
	canonical->args[2] = canonical->args[1];
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = -1;
	return redirect_enter(wait4);
}

SYSCALL_POST_CALL_PROT(wait3)
{
	return redirect_post_call(wait4);
}

SYSCALL_EXIT_PROT(wait3)
{
	redirect_exit(wait4);
	return 0;
}


/* ************************************************************************** *
 * wait4                                                                      *
 * pid_t wait4(pid_t pid, int *wstatus, int options,                          * 
 *             struct rusage *rusage);                                        *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(wait4)
{
	/* TODO -- Ignore rusage argument for now. */
	actual->args[3] = 0;
	return redirect_enter(waitpid);
}

SYSCALL_POST_CALL_PROT(wait4)
{
	return redirect_post_call(waitpid);
}

SYSCALL_EXIT_PROT(wait4)
{
	return redirect_exit(waitpid);
}


/* ************************************************************************** *
 * setitimer                                                                  *
 * int setitimer(int which, const struct itimerval *restrict new_value,       *
 *               struct itimerval *restrict old_value);                       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(setitimer)
{
	struct setitimer_scratch {
		struct type itimerval_type;
	};
	alloc_scratch(sizeof(struct setitimer_scratch));
	struct setitimer_scratch *_scratch = 
		(struct setitimer_scratch *)*scratch;
	_scratch->itimerval_type = BUFFER_TYPE(sizeof(struct itimerval));
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = POINTER_TYPE(&_scratch->itimerval_type);
	canonical->arg_types[2] = POINTER_TYPE(&_scratch->itimerval_type);
	canonical->arg_flags[2] = ARG_FLAG_WRITE_ONLY;
	return DISPATCH_CHECKED | DISPATCH_EVERYONE;
}

SYSCALL_EXIT_PROT(setitimer)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * kill                                                                       *
 * int kill(pid_t pid, int sig)                                               *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(kill)
{
	struct pid_info *pi = get_pid_info(0);
	remap_pid(pi, 0);
	canonical->arg_types[0] = IMMEDIATE_TYPE(pid_t);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}


/* ************************************************************************** *
 * rt_sigaction                                                               *
 * Currently signal handlers are not supported; we skip any registrations,.   *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(rt_sigaction)
{
	int dispatch = DISPATCH_UNCHECKED;
	actual->ret = 0;
	canonical->ret = 0;
	dispatch |= DISPATCH_SKIP;
	return dispatch;
}


/* ************************************************************************** *
 * readlink                                                                   *
 * ssize_t readlink(const char *restrict pathname, char *restrict buf,        *
 *                  size_t bufsiz);                                           *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(readlink)
{
	canonical->no = SYSCALL_readlinkat_CANONICAL;
	canonical->args[3] = canonical->args[2];
	canonical->args[2] = canonical->args[1];
	canonical->args[1] = canonical->args[0];
	canonical->args[0] = AT_FDCWD;
	actual->no = __NR_readlinkat;
	actual->args[3] = actual->args[2];
	actual->args[2] = actual->args[1];
	actual->args[1] = actual->args[0];
	actual->args[0] = AT_FDCWD;
	return redirect_enter(readlinkat);
}

SYSCALL_EXIT_PROT(readlink)
{
	return redirect_exit(readlinkat);
}


/* ************************************************************************** *
 * readlinkat                                                                 *
 * ssize_t readlinkat(int dirfd, const char *restrict pathname,               *
 *                    char *restrict buf, size_t bufsiz);                     *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(readlinkat)
{
	alloc_scratch(2 * sizeof(struct type));
	struct type *ref_types = (struct type *)*scratch;
	size_t bufsiz = actual->args[3];

	struct descriptor_info *di = NULL;
	if(AT_FDCWD != (int)actual->args[0]) {
		get_di(0);
		remap_fd(di, 0);
	}

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[0]);
	ref_types[0] = STRING_TYPE();
	canonical->arg_types[2] = POINTER_TYPE(&ref_types[1]);
	canonical->arg_flags[2] = ARG_FLAG_REPLICATE | ARG_FLAG_WRITE_ONLY;
	ref_types[1] = BUFFER_TYPE(bufsiz);
	canonical->arg_types[3] = IMMEDIATE_TYPE(long);

	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(readlinkat)
{
	free_scratch();
	return 0;
}

/* ************************************************************************** *
 * pipe                                                                       *
 * int pipe(int pipefd[2])                                                    *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(pipe)
{
	canonical->no = SYSCALL_pipe2_CANONICAL;
	canonical->args[1] = 0;
	return redirect_enter(pipe2);
}

SYSCALL_EXIT_PROT(pipe)
{
	return redirect_exit(pipe2);
}


/* ************************************************************************** *
 * pipe2                                                                      *
 * int pipe2(int pipefd[2], int flags);                                       *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(pipe2)
{
	alloc_scratch(sizeof(struct type));
	struct type *ref_type = (struct type *)*scratch;
	canonical->arg_types[0] = POINTER_TYPE(ref_type);
	*ref_type               = BUFFER_TYPE(2 * sizeof(long));
	canonical->arg_flags[0] = ARG_FLAG_WRITE_ONLY;
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	// Do not cross-check flags that are encoded differently for now
	canonical->args[2] &= ~(O_DIRECT);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(pipe2)
{
	free_scratch();
	struct descriptor_info *dis[2];
	if(0 > actual->ret) {
		return 0;
	}
	int *pipefd = (int *)actual->args[0];
#if VERBOSITY >= 4
	SAFE_LOGF("%s adding descriptor.\n", handler->name);
#endif
	int flags = DI_OPENED_LOCALLY;
	int local_fd = -1;
	enum descriptor_type type = (enum descriptor_type)PIPE_DESCRIPTOR;
	dis[0] = env_add_local_descriptor(env, pipefd[0], flags, type);
	dis[1] = env_add_local_descriptor(env, pipefd[1], flags, type);
	pipefd[0] = env_canonical_fd_for(env, dis[0]);
	pipefd[1] = env_canonical_fd_for(env, dis[1]);
	return 0;
}


/* ************************************************************************** *
 * rename                                                                     *
 * int rename(const char *oldpath, const char *newpath);                      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(rename)
{
	canonical->no = SYSCALL_renameat2_CANONICAL;
	actual->no = __NR_renameat2;
	canonical->args[1] = canonical->args[0];
	actual->args[1] = actual->args[0];
	canonical->args[3] = canonical->args[1];
	actual->args[3] = actual->args[1];
	canonical->args[0] = AT_FDCWD;
	actual->args[0] = AT_FDCWD;
	canonical->args[2] = AT_FDCWD;
	actual->args[2] = AT_FDCWD;
	canonical->args[4] = 0;
	actual->args[4] = 0;
	return redirect_enter(renameat2);
}

SYSCALL_EXIT_PROT(rename)
{
	return redirect_exit(renameat2);
}


/* ************************************************************************** *
 * renameat                                                                   *
 * int renameat(int olddirfd, const char *oldpath,                            * 
 *              int newdirfd, const char *newpath);                           *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(renameat)
{
	canonical->no = SYSCALL_renameat2_CANONICAL;
	actual->no = __NR_renameat2;
	canonical->args[4] = 0;
	actual->args[4] = 0;
	return redirect_enter(renameat2);
}

SYSCALL_EXIT_PROT(renameat)
{
	return redirect_exit(renameat2);
}


/* ************************************************************************** *
 * renameat2                                                                  *
 * int renameat2(int olddirfd, const char *oldpath,                           * 
 *               int newdirfd, const char *newpath, unsigned int flags);      *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(renameat2)
{
	alloc_scratch(2 * sizeof(struct type));
	struct type *oldpath_str_type = (struct type *)*scratch;
	struct type *newpath_str_type = (struct type *)(*scratch 
	                                                + sizeof(struct type));
	struct descriptor_info *oldpath_di = NULL;
	struct descriptor_info *newpath_di = NULL;
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	if(AT_FDCWD != (int)canonical->args[0]) {
		oldpath_di = get_di(0);
		remap_fd(oldpath_di, 0);
	}
	canonical->arg_types[1] = POINTER_TYPE(oldpath_str_type);
	*oldpath_str_type = STRING_TYPE();
	canonical->arg_types[2] = DESCRIPTOR_TYPE();
	if(AT_FDCWD != (int)canonical->args[0]) {
		newpath_di = get_di(2);
		remap_fd(newpath_di, 2);
	}
	canonical->arg_types[3] = POINTER_TYPE(newpath_str_type);
	*newpath_str_type = STRING_TYPE();
	canonical->arg_types[4] = IMMEDIATE_TYPE(int);
	return DISPATCH_CHECKED
	       | dispatch_leader_if_needed(oldpath_di, 0)
               | dispatch_leader_if_needed(newpath_di, 0);
}

SYSCALL_EXIT_PROT(renameat2)
{
	free_scratch();
	return 0;
}


/* ************************************************************************** *
 * unlink                                                                     *
 * int unlink(const char *pathname);                                          *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(unlink)
{
	canonical->no = SYSCALL_unlinkat_CANONICAL;
	canonical->args[0] = AT_FDCWD;
	canonical->args[1] = canonical->args[0];
	return redirect_enter(unlinkat);
}

SYSCALL_EXIT_PROT(unlink)
{
	return redirect_exit(unlinkat);
}


/* ************************************************************************** *
 * unlinkat                                                                   *
 * int unlinkat(int dirfd, const char *pathname, int flags);                  *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(unlinkat)
{
	alloc_scratch(sizeof(struct type));
	struct type *pathname_type = (struct type*)*scratch;
	struct descriptor_info *pathname_di = NULL;
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	if(AT_FDCWD != (int)canonical->args[0]) {
		pathname_di = get_di(0);
		remap_fd(pathname_di, 0);
	}
	canonical->arg_types[1] = POINTER_TYPE(pathname_type);
	*pathname_type = STRING_TYPE();
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	return dispatch_leader_if_needed(pathname_di, DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(unlinkat)
{
	free_scratch();
	return 0;
}


