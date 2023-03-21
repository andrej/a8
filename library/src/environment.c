#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include "environment.h"
#include "communication.h"
#include "util.h"
#include "unprotected.h"

int env_init(struct environment *env, bool is_leader)
{
	struct pid_info *pi;

	env->epoll_data_infos = (struct epoll_data_infos){};
	env->is_leader = is_leader;

	// stdin
	SAFE_Z_TRY_EXCEPT(
		env_add_descriptor(env, 0, 0, DI_OPENED_ON_LEADER, 
	                           (enum descriptor_type)FILE_DESCRIPTOR),
		return 1);

	// stdout
	SAFE_Z_TRY_EXCEPT(
		env_add_descriptor(env, 1, 1, DI_OPENED_LOCALLY, 
	                           (enum descriptor_type)FILE_DESCRIPTOR),
		return 1);

	// stderr
	SAFE_Z_TRY_EXCEPT(
		env_add_descriptor(env, 2, 2, DI_OPENED_LOCALLY, 
	                           (enum descriptor_type)FILE_DESCRIPTOR),
		return 1);
	
	SAFE_Z_TRY_EXCEPT(
		env->pid = env_add_local_pid_info(env, getpid()),
		return 1);
	SAFE_Z_TRY_EXCEPT(
		env->ppid = env_add_local_pid_info(env, getppid()),
		return 1);

	return 0;
}

struct epoll_data_info *get_epoll_data_info_for(struct environment *env,
                                                int epfd,
						int fd,
						uint32_t events)
{
	struct epoll_data_info *info = 
		(struct epoll_data_info *)env->epoll_data_infos.head;
	while(NULL != info) {
		if(info->epfd == epfd && info->fd == fd
		   && (info->event.events & events)) {
			return info;
		}
		info = info->next;
	}
	return NULL;
}

struct epoll_data_info *purge_epoll_data_fd(struct environment *env, int fd)
{
	struct epoll_data_info *info =
		(struct epoll_data_info *)env->epoll_data_infos.head;
	struct epoll_data_info *next;
	/* FIXME: The current implementation does not address the following 
	   subtlety:

	   Will closing a file descriptor cause it to be removed from
           all epoll interest lists?

           Yes, but be aware of the following point.  A file descriptor
           is a reference to an open file description (see open(2)).
           Whenever a file descriptor is duplicated via dup(2), dup2(2),
           fcntl(2) F_DUPFD, or fork(2), a new file descriptor referring
           to the same open file description is created.  An open file
           description continues to exist until all file descriptors
           referring to it have been closed.

           A file descriptor is removed from an interest list only after
           all the file descriptors referring to the underlying open
           file description have been closed. */
	while(NULL != info) {
		next = info->next;
		if(info->fd == fd) {
			remove_epoll_data_info(env, info);
		}
		info = next;
	}
}

int append_epoll_data_info(struct environment *env, 
                           struct epoll_data_info info)
{
	if(NULL != 
	   get_epoll_data_info_for(env, info.epfd, info.fd, info.event.events)){
		SAFE_WARNF("An epoll_info entry for (%d, %d, %x) already "
		           "exists.\n", info.epfd, info.fd, info.event.events);
		return 1;
	}
	struct epoll_data_info *to_insert = malloc(sizeof(info));
	if(NULL == to_insert) {
		return 1;
	}
	memcpy(to_insert, &info, sizeof(struct epoll_data_info));
	struct epoll_data_info *tail = env->epoll_data_infos.tail;
	if(NULL != tail) {
		to_insert->prev = tail;
		tail->next = to_insert;
	} else {
		env->epoll_data_infos.head = to_insert;
		to_insert->prev = NULL;
	}
	to_insert->next = NULL;
	env->epoll_data_infos.tail = to_insert;
	return 0;
}

int remove_epoll_data_info(struct environment *env, 
                           struct epoll_data_info *info)
{
	if(info == env->epoll_data_infos.head) {
		env->epoll_data_infos.head = info->next;
	}
	if(info == env->epoll_data_infos.tail) {
		env->epoll_data_infos.tail = info->prev;
	}
	if(NULL != info->prev) {
		info->prev->next = info->next;
	}
	if(NULL != info->next) {
		info->next->prev = info->prev;
	}
	free(info);
	return 0;
}

int 
__attribute__((section("unprotected")))
checkpointed_environment_fix_up(struct environment *env)
{
	/* epoll has somewhat unintuitive behavior across fork() compared to 
	   other file descriptors, outlined further below in this discussion
	   https://groups.google.com/g/fa.linux.kernel/c/LH9hqwpeyuw 
	   And also here: 
	   https://linux-kernel.vger.kernel.narkive.com/uiXa4faI/epoll-and-fork
	   
	   Essentially, changing the observed set of file descriptors in the
	   parent will also change it in the child. This can lead to errors
	   when the child tries to do an epoll_ctl(epfd ... fd) operation, when
	   fd has since been removed from epfd in the parent. 
	   
	   We circumvent the issue by recreating the epoll epfd as a new 
	   separate one. A simple dup() does *not* suffice for this; it will
	   reference the same epoll structure in the kernel. We must recreate
	   the epoll as a new structure via epoll_create() and epoll_ctl(). */

	size_t i = 0;
	list_for_each(env->descriptors, i) {
		if(!list_item_is_occupied(env->descriptors, i)) {
			continue;
		}
		struct descriptor_info * const di = 
			list_get_i(env->descriptors, i);
		int new_fd = 0;
		const int old_fd = di->local_fd;
		const int canonical_fd = di - env->descriptors.items; 
			// TODO add bounds check
		int s = 0;
		if(di->type != EPOLL_DESCRIPTOR ||
		   !is_open_locally(env, di)) {
			continue;
		}
		new_fd = unprotected_funcs.epoll_create1(0);
			// FIXME: copy CLOEXEC flag from original epoll
		if(-1 == new_fd) {
			SAFE_WARNF("Cannot recreate epoll file descriptor: %d\n", 
			          errno);
			return 1;
		}
		unprotected_funcs.close(old_fd);
		di->local_fd = new_fd;
		/* Add back all the listened-for fds. */
		struct epoll_data_info *j = NULL;
		for_each_epoll_data_info(env->epoll_data_infos, j) {
			if(j->epfd != canonical_fd) {
				continue;
			}
			const struct descriptor_info *fd_di = 
				list_get_i(env->descriptors, j->fd);
				// TODO add bounds check
			s = unprotected_funcs.epoll_ctl(
				new_fd, EPOLL_CTL_ADD, fd_di->local_fd,
				&j->event);
			if(0 != s) {
				SAFE_WARNF("epoll_ctl failed for fd %d while "
				          "trying to recreate epoll %d\n",
					  canonical_fd, j->fd);
				return 1;
			}
		}
	}
	return 0;
}
