#ifndef VMA_REDIRECT_H
#define VMA_REDIRECT_H

/**
 * This file overwrites socket functions with ones loaded from the libvma.so
 * library for better intra-monitor communication if the "USE_LIBVMA" build flag
 * is set. Otherwise, regular sockets are used.
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#define _GNU_SOURCE
#include <poll.h>
#include "build_config.h"
#include "util.h"
#if !USE_LIBVMA
#define maybeconst const
#include "socket_fptr_t.h"
#else
#define maybeconst
#include "socket_fptr_t.h"
#endif

#define SOCKET_FNS(X) \
	X(socket) \
	X(close) \
	X(shutdown) \
	X(accept) \
	X(bind) \
	X(connect) \
	X(listen) \
	X(setsockopt) \
	X(getsockopt) \
	X(fcntl) \
	X(ioctl) \
	X(getsockname) \
	X(getpeername) \
	X(read) \
	X(readv) \
	X(recv) \
	X(recvmsg) \
	/*X(recvmmsg)*/ \
	X(recvfrom) \
	X(write) \
	X(writev) \
	X(send) \
	X(sendmsg) \
	/*X(sendmmsg)*/ \
	X(sendto) \
	X(select) \
	X(pselect) \
	X(poll) \
	/*X(ppoll)*/ \
	X(epoll_create) \
	X(epoll_create1) \
	X(epoll_ctl) \
	X(epoll_wait) \
	X(epoll_pwait) \
	X(socketpair) \
	X(pipe) \
	X(open) \
	X(creat) \
	X(dup) \
	X(dup2) \
	/*X(clone)*/ \
	X(fork) \
	X(vfork) \
	X(daemon) \
	X(sigaction)

#define DEFINE_SOCKPTR_STRUCT(fn) fn##_fptr_t fn;
struct socket_fptrs {
	SOCKET_FNS(DEFINE_SOCKPTR_STRUCT);
};


#if !USE_LIBVMA
#define DEFINE_REGULAR_SOCKET_FN(fn) .fn = &fn,
static const struct socket_fptrs s = {
	SOCKET_FNS(DEFINE_REGULAR_SOCKET_FN)
};
static inline int init_vma_redirect() {
	return 0;
}
#else

static struct socket_fptrs s = {};
static inline int init_vma_redirect() {
	if(NULL != s.socket) {
		// Already initialized.
		return 0;
	}
	void *handle = NULL;
	Z_TRY(handle = dlopen("/usr/lib/libvma.so", RTLD_NOW));
	#define DEFINE_LIBVMA_SOCKET_FN(fn) s.fn = (fn##_fptr_t)\
							dlsym(handle, #fn);
	SOCKET_FNS(DEFINE_LIBVMA_SOCKET_FN);
	return 0;
}

#endif

#endif