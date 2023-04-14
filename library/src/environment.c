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

	SAFE_Z_TRY_EXCEPT(env->epoll_data_infos =
	                  calloc(1, sizeof(struct epoll_data_info_list)),
			  return 1);

	return 0;
}

struct epoll_data_info *get_epoll_data_info_for(struct environment *env,
                                                int epfd,
						int fd,
						uint32_t events)
{
	size_t i = 0;
	list_for_each(*env->epoll_data_infos, i) {
		if(!list_item_is_occupied(*env->epoll_data_infos, i)) {
			continue;
		}
		struct epoll_data_info *info = 
			list_get_i(*env->epoll_data_infos, i);
		if(info->epfd == epfd && info->fd == fd
		   && (info->event.events & events)) {
			return info;
		}
	}
	return NULL;
}

int purge_epoll_data_fd(struct environment *env, int fd)
{
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
	size_t i = 0;
	list_for_each(*env->epoll_data_infos, i) {
		if(!list_item_is_occupied(*env->epoll_data_infos, i)) {
			continue;
		}
		struct epoll_data_info *info = 
			list_get_i(*env->epoll_data_infos, i);
		if(info->fd == fd) {
			SAFE_NZ_TRY_EXCEPT(remove_epoll_data_info(env, info),
			                   return 1);
			/* When checkpointing, there may remain other 
			   processes that refer to `fd`. This causes that
			   file description to remain open, and epoll will 
			   continue notifying for it -- not what we the program
			   expects, so we must remove it here. Note that this 
			   removal may fail if the target program already 
			   removed it, in which case we silently ignore it. */
			struct descriptor_info *epfd_di, *fd_di;
			epfd_di = env_get_canonical_descriptor_info(env, 
			                                            info->epfd);
			fd_di = env_get_canonical_descriptor_info(env, fd);
			if(NULL != epfd_di && NULL != fd_di
			   && is_open_locally(env, epfd_di)
			   && is_open_locally(env, fd_di)) {
				int s = epoll_ctl(epfd_di->local_fd, EPOLL_CTL_DEL, 
				                  fd_di->local_fd, NULL);
			}
		}
	}
	return 0;
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
	int s = list_put(*env->epoll_data_infos, info);
	SAFE_LZ_TRY_EXCEPT(s, return 1);
#if VERBOSITY >= 4
	SAFE_LOGF("Appended epoll data info (%d, %d, %x) at index %d.\n",
	          info.epfd, info.fd, info.event.events, s);
#endif
	return 0;
}

int remove_epoll_data_info(struct environment *env, 
                           struct epoll_data_info *info)
{
	size_t i = info 
	           - (struct epoll_data_info *)env->epoll_data_infos->items;
	int s = list_del_i(*env->epoll_data_infos, i);
	SAFE_NZ_TRY_EXCEPT(s, return 1);
#if VERBOSITY >= 4
	SAFE_LOGF("Removed epoll data info (%d, %d, %x) at index %lu.\n",
	          info->epfd, info->fd, info->event.events, i);
#endif
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
		const int canonical_fd = env_canonical_fd_for(env, di); 
			// TODO add bounds check
		int s = 0;
		if(di->type != EPOLL_DESCRIPTOR ||
		   !is_open_locally(env, di)) {
			continue;
		}
		new_fd = epoll_create1(0);
			// FIXME: copy CLOEXEC flag from original epoll
		if(-1 == new_fd) {
			SAFE_WARNF("Cannot recreate epoll file descriptor: "
			           "%d\n", errno);
			return 1;
		}
		close(old_fd);
		di->local_fd = new_fd;
		/* Add back all the listened-for fds. */
		size_t j = 0;
		list_for_each(*env->epoll_data_infos, j) {
			if(!list_item_is_occupied(*env->epoll_data_infos, j)) {
				continue;
			}
			struct epoll_data_info *j_item = 
				list_get_i(*env->epoll_data_infos, j);
			if(j_item->epfd != canonical_fd) {
				continue;
			}
			const struct descriptor_info *fd_di = 
				list_get_i(env->descriptors, j_item->fd);
				// TODO add bounds check
			struct epoll_event custom_event = {
				.events = j_item->event.events,
				.data.fd = j_item->fd
			};
			s = epoll_ctl(new_fd, EPOLL_CTL_ADD, fd_di->local_fd,
				      &custom_event);
			if(0 != s) {
				SAFE_WARNF("epoll_ctl failed for fd %d while "
				          "trying to recreate epoll %d\n",
					  canonical_fd, j_item->fd);
				return 1;
			}
		}
	}
	return 0;
}
