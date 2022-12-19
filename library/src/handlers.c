#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>

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
	actual->args[arg_i] = (di)->local_fd; \
}

#define alloc_scratch(sz) { \
	*scratch = calloc(sz, 1); \
	if(NULL == scratch) { \
		return DISPATCH_ERROR; \
	} \
}

#define free_scratch() { \
	if(NULL != scratch && NULL != *scratch) { \
		free(*scratch); \
	} \
}

#define dispatch_leader_if_needed(di, addl_flags) ({ \
	int flags = addl_flags; \
	if((di)->flags & DI_OPENED_ON_LEADER) { \
		flags |= DISPATCH_LEADER | DISPATCH_NEEDS_REPLICATION; \
	} else { \
		flags |= DISPATCH_EVERYONE; \
	} \
	flags; \
})

#define is_open_locally(env, di) \
	((di->flags & DI_OPENED_LOCALLY) \
	 || (env->is_leader && (di->flags & DI_OPENED_ON_LEADER)))

/* TODO: monitor opens some file descriptors itself, e.g. for logging, 
   sockets for intra-monitor commmunication, etc. If the variant requests to
   use these fds via dup2/dup3, we currently error (could also remap to 
   arbitrary fd instead, transparently to variant). */
#define is_monitor_fd(fd) \
	0

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
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	remap_fd(di, 0);
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
	if(dispatch & DISPATCH_EVERYONE) {
		di = env_add_local_descriptor(env, actual->ret, 
		                             DI_OPENED_LOCALLY);
	} else if(env->is_leader) {
		di = env_add_local_descriptor(env, actual->ret, 
		                             DI_OPENED_ON_LEADER);
	} else {
		di = env_add_local_descriptor(env, -1, DI_OPENED_ON_LEADER);
	}
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
	int flags = actual->args[3];
	struct descriptor_info *di = NULL;

	if(!(flags & (MAP_ANON | MAP_ANONYMOUS))) {
		di = get_di(4);
		if(di->flags & DI_OPENED_ON_LEADER) {
			/* A memory-mapped file must be open locally; we do not 
			   support a "remote" memory-mapped file. */
			return DISPATCH_ERROR;
		}
	}

	canonical->args[0] = ((void *)canonical->args[0] == NULL ? 0 : 1);
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(size_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->arg_types[3] = IMMEDIATE_TYPE(int);
	canonical->arg_types[4] = DESCRIPTOR_TYPE();
	if(NULL != di) {
		remap_fd(di, 4);
	}

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
 * stat                                                                       * 
 *                                                                            *
 * int fstat(cons char *restrict pathname,                                    *
 *           struct stat *restrict statbuf);                                  * 
 * ************************************************************************** */

SYSCALL_ENTER_PROT(stat)
{
	alloc_scratch(sizeof(struct type) * 2);
	struct type *ref_types = (struct type *)*scratch;

	canonical->arg_types[0] = POINTER_TYPE(&ref_types[0]);
	ref_types[0]            = STRING_TYPE();
	canonical->arg_types[1] = POINTER_TYPE(&ref_types[1]);
	ref_types[1]            = BUFFER_TYPE(sizeof(struct stat));
	canonical->arg_flags[1] = ARG_FLAG_WRITE_ONLY | ARG_FLAG_REPLICATE;
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	// TODO check if it is a leader-only file
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(stat)
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
	alloc_scratch(sizeof(struct type));
	struct type *stat_buf_type = (struct type *)*scratch;

	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	remap_fd(di, 0);
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
 * int dup3(int oldfd, int newfd);                                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(dup2)
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
	canonical->ret_type = DESCRIPTOR_TYPE();
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	if(oldfd == newfd) {
		// dup3 returns an error value in this case
		actual->ret = oldfd;
		return DISPATCH_SKIP | DISPATCH_CHECKED;
	}

	return dispatch_leader_if_needed(di[0], DISPATCH_CHECKED);
}

SYSCALL_EXIT_PROT(dup2)
{
	int newfd = canonical->args[1];

	if(0 > actual->ret) {
		goto ret;
	}

	struct descriptor_info **di = (struct descriptor_info **)*scratch;

	if(NULL != di[1]) {
		/* newfd will override a fd previously opened by the variant. 
		   old local fd was closed by a successful dup2 call. */
		env_del_descriptor(env, di[1]);
	}

	int local_fd = -1;
	if(is_open_locally(env, di[0])) {
		local_fd = actual->ret;
	}
	Z_TRY_EXCEPT(env_add_descriptor(env, local_fd, newfd, di[0]->flags),
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
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(off_t);
	canonical->arg_types[2] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return dispatch_leader_if_needed(di, DISPATCH_CHECKED);
}


/* ************************************************************************** *
 * socket                                                                     *
 *                                                                            *
 * int socket(int domain, int type, int protocol);                            *
 * ************************************************************************** */

SYSCALL_ENTER_PROT(socket)
{
	canonical->arg_types[0] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;
	return DISPATCH_LEADER | DISPATCH_CHECKED
		| DISPATCH_NEEDS_REPLICATION;
}

SYSCALL_EXIT_PROT(socket)
{
	size_t i = 0;
	struct descriptor_info *di = NULL;
	if(env->is_leader) {
		di = env_add_local_descriptor(env, actual->ret, 
		                             DI_OPENED_ON_LEADER);
	} else {
		di = env_add_local_descriptor(env, -1, DI_OPENED_ON_LEADER);
	}
	if(NULL == di) {
		actual->ret = -1;
		return;
	}
	actual->ret = di->canonical_fd;
	return;
}


/* ************************************************************************** *
 * epoll_create                                                               *
 *                                                                            *
 * int epoll_create(int size);                                                *
 * ************************************************************************** */

SYSCALL_EXIT_PROT(epoll_create)
{
	struct descriptor_info *di =
		env_add_local_descriptor(env, actual->ret, DI_OPENED_LOCALLY);
	if(NULL == di) {
		actual->ret = -1;
		return;
	}
	actual->ret = di->canonical_fd;
}


/* ************************************************************************** * * epoll_ctl                                                                  *
 *                                                                            *
 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);        *
 * ************************************************************************** */
 
SYSCALL_ENTER_PROT(epoll_ctl)
{
	struct scratch {
		struct type ref_types[2];
		struct buffer_reference buf_refs[1];
		struct descriptor_info *di[2];
	};
	alloc_scratch(sizeof(struct scratch));
	struct scratch *s = (struct scratch *)*scratch;

	int op = canonical->args[1];
	struct epoll_event *event = (struct epoll_event *)canonical->args[3];

	s->di[0] = get_di(0);
	s->di[1] = get_di(2);

	/* Argument serialization */
	canonical->arg_types[0] = DESCRIPTOR_TYPE();
	canonical->arg_types[1] = IMMEDIATE_TYPE(int);
	canonical->arg_types[2] = DESCRIPTOR_TYPE();
	canonical->arg_types[3] = POINTER_TYPE(&s->ref_types[0]);
	s->ref_types[0]         = BUFFER_TYPE(sizeof(struct epoll_event),
	                                      1, s->buf_refs);
	s->buf_refs[0]          = (struct buffer_reference)
	                          {.offset = 
				     ((void *)&event->data.ptr)-((void*)&event),
	                           .type = &s->ref_types[1]};
	s->ref_types[1]         = IGNORE_TYPE();
	canonical->ret_type = IMMEDIATE_TYPE(long);
	canonical->ret_flags = ARG_FLAG_REPLICATE;

	/* File descriptor remapping */
	remap_fd(s->di[0], 0);
	remap_fd(s->di[1], 2);

	/* If epfd is only open on the leader, only dispatch there.
	   If epfd is open everywhere, but fd is only on the leader, then this
	   means that epfd it is about to become associated with a leader-only
	   file. This association can only happen on the leader. The exit 
	   handler will then also "taint" epfd to be a leader-only handle. */
	if(s->di[0]->flags & DI_OPENED_ON_LEADER
	   || s->di[1]->flags & DI_OPENED_ON_LEADER) {
		return DISPATCH_LEADER | DISPATCH_CHECKED
		       | DISPATCH_NEEDS_REPLICATION;
	}

	/* TODO might just always do leader-only dispatch instead... Cannot
	   currently think of a time where this makes sense. */
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;

}

SYSCALL_EXIT_PROT(epoll_ctl)
{
	int epfd = canonical->args[0];
	int op = canonical->args[1];
	int fd = canonical->args[2];
	struct epoll_event *event = (struct epoll_event *)canonical->args[3];
	struct epoll_data_info info;
	info.epfd = epfd;
	info.fd = fd;
	if(NULL != event) {
		info.data = *event;
	}

	struct scratch {
		struct type ref_types[2];
		struct buffer_reference buf_refs[1];
		struct descriptor_info *di[2];
	};
	struct scratch *s = (struct scratch *)*scratch;	

	if(dispatch & DISPATCH_LEADER
	   && s->di[0]->flags & DI_OPENED_LOCALLY) {
		if(!env->is_leader) {
			close(s->di[0]->local_fd);
		}
		s->di[0]->flags &= ~DI_OPENED_LOCALLY;
		s->di[0]->flags |= DI_OPENED_ON_LEADER;
	}


	switch(op) {
		case EPOLL_CTL_ADD: {
			if(NULL == event) {
				actual->ret = -1;
				return;
			}
			append_epoll_data_info(env, info);
			break;
		}
		case EPOLL_CTL_MOD: {
			struct epoll_data_info *existing_info =
				get_epoll_data_info_for(env, epfd, fd, ~0U);
			if(NULL == event
			   || NULL == existing_info) {
				actual->ret = -1;
				return;
			}
			memcpy(&existing_info->data, event,
			       sizeof(struct epoll_event));
			break;
		}
		case EPOLL_CTL_DEL: {
			struct epoll_data_info *existing_info =
				get_epoll_data_info_for(env, epfd, fd, ~0U);
			if(NULL == existing_info) {
				actual->ret = -1;
				return;
			}
			remove_epoll_data_info(env, existing_info);
			break;
		}
	}

	free_scratch();
}


SYSCALL_ENTER_PROT(epoll_wait)
{
	return DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(epoll_wait)
{

}
