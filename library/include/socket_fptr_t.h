#ifndef SOCKET_FPTR_T_H
#define SOCKET_FPTR_T_H

/* Needed for vma_redirect.h, adapted from Mellanox sockperf sources. */

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/poll.h>
#include <sched.h>
#include <sys/ioctl.h>
//#include <resolv.h> // conflicts with elf.h p_type
#include <sys/epoll.h>
#include <sys/socket.h>

// --------------------------------------------------------------------------
//  function pointer type defs
//  Source: https://github.com/Mellanox/sockperf/blob/sockperf_v2/src/vma-redirect.h
//  Copyright (c) 2011-2021 Mellanox Technologies Ltd.
//  All rights reserved.
// 
//  Redistribution and use in source and binary forms, with or without modification,
//  are permitted provided that the following conditions are met:
// 
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//  3. Neither the name of the Mellanox Technologies Ltd nor the names of its
//     contributors may be used to endorse or promote products derived from this
//     software without specific prior written permission.
// 
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
//  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
//  SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
//  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
//  OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
//  OF SUCH DAMAGE.
// --------------------------------------------------------------------------

typedef int (* maybeconst socket_fptr_t)(int __domain, int __type, int __protocol);
typedef int (* maybeconst close_fptr_t)(int __fd);
typedef int (* maybeconst shutdown_fptr_t)(int __fd, int __how);

typedef int (* maybeconst accept_fptr_t)(int __fd, struct sockaddr *__addr, socklen_t *__addrlen);
typedef int (* maybeconst bind_fptr_t)(int __fd, const struct sockaddr *__addr, socklen_t __addrlen);
typedef int (* maybeconst connect_fptr_t)(int __fd, const struct sockaddr *__to, socklen_t __tolen);
typedef int (* maybeconst listen_fptr_t)(int __fd, int __backlog);

typedef int (* maybeconst setsockopt_fptr_t)(int __fd, int __level, int __optname, __const void *__optval,
                                 socklen_t __optlen);
typedef int (* maybeconst getsockopt_fptr_t)(int __fd, int __level, int __optname, void *__optval,
                                 socklen_t *__optlen);
typedef int (* maybeconst fcntl_fptr_t)(int __fd, int __cmd, ...);
typedef int (* maybeconst ioctl_fptr_t)(int __fd, unsigned long __request, ...);
typedef int (* maybeconst getsockname_fptr_t)(int __fd, struct sockaddr *__name, socklen_t *__namelen);
typedef int (* maybeconst getpeername_fptr_t)(int __fd, struct sockaddr *__name, socklen_t *__namelen);

typedef ssize_t (* maybeconst read_fptr_t)(int __fd, void *__buf, size_t __nbytes);
typedef ssize_t (* maybeconst readv_fptr_t)(int __fd, const struct iovec *iov, int iovcnt);
typedef ssize_t (* maybeconst recv_fptr_t)(int __fd, void *__buf, size_t __n, int __flags);
typedef ssize_t (* maybeconst recvmsg_fptr_t)(int __fd, struct msghdr *__message, int __flags);
// typedef ssize_t (* maybeconst recvmmsg_fptr_t)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
//                                    int __flags, const struct timespec *__timeout);
typedef ssize_t (* maybeconst recvfrom_fptr_t)(int __fd, void *__restrict __buf, size_t __n, int __flags,
                                   struct sockaddr *__from, socklen_t *__fromlen);

typedef ssize_t (* maybeconst write_fptr_t)(int __fd, __const void *__buf, size_t __n);
typedef ssize_t (* maybeconst writev_fptr_t)(int __fd, const struct iovec *iov, int iovcnt);
typedef ssize_t (* maybeconst send_fptr_t)(int __fd, __const void *__buf, size_t __n, int __flags);
typedef ssize_t (* maybeconst sendmsg_fptr_t)(int __fd, __const struct msghdr *__message, int __flags);
// typedef ssize_t (* maybeconst sendmmsg_fptr_t)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
//                                    int __flags);
typedef ssize_t (* maybeconst sendto_fptr_t)(int __fd, __const void *__buf, size_t __n, int __flags,
                                 const struct sockaddr *__to, socklen_t __tolen);

typedef int (* maybeconst select_fptr_t)(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                             struct timeval *__timeout);
typedef int (* maybeconst pselect_fptr_t)(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__errorfds,
                              const struct timespec *__timeout, const sigset_t *__sigmask);

typedef int (* maybeconst poll_fptr_t)(struct pollfd *__fds, nfds_t __nfds, int __timeout);
typedef int (* maybeconst ppoll_fptr_t)(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout,
                            const sigset_t *__sigmask);
typedef int (* maybeconst epoll_create_fptr_t)(int __size);
typedef int (* maybeconst epoll_create1_fptr_t)(int __flags);
typedef int (* maybeconst epoll_ctl_fptr_t)(int __epfd, int __op, int __fd, struct epoll_event *__event);
typedef int (* maybeconst epoll_wait_fptr_t)(int __epfd, struct epoll_event *__events, int __maxevents,
                                 int __timeout);
typedef int (* maybeconst epoll_pwait_fptr_t)(int __epfd, struct epoll_event *__events, int __maxevents,
                                  int __timeout, const sigset_t *sigmask);

typedef int (* maybeconst socketpair_fptr_t)(int __domain, int __type, int __protocol, int __sv[2]);
typedef int (* maybeconst pipe_fptr_t)(int __filedes[2]);
typedef int (* maybeconst open_fptr_t)(__const char *__file, int __oflag, ...);
typedef int (* maybeconst creat_fptr_t)(const char *__pathname, mode_t __mode);
typedef int (* maybeconst dup_fptr_t)(int fildes);
typedef int (* maybeconst dup2_fptr_t)(int fildes, int fildes2);

typedef int (* maybeconst clone_fptr_t)(int (*__fn)(void *), void *__child_stack, int __flags, void *__arg);
typedef pid_t (* maybeconst fork_fptr_t)(void);
typedef pid_t (* maybeconst vfork_fptr_t)(void);
typedef int (* maybeconst daemon_fptr_t)(int __nochdir, int __noclose);
typedef int (* maybeconst sigaction_fptr_t)(int signum, const struct sigaction *act, struct sigaction *oldact);

#endif