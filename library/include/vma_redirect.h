#ifndef VMA_REDIRECT_H
#define VMA_REDIRECT_H

/**
 * This file overwrites socket functions with ones loaded from the libvma.so
 * library for better intra-monitor communication if the "USE_LIBVMA" build flag
 * is set. Otherwise, regular sockets are used.
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <poll.h>
#include <stdbool.h>
#include "build_config.h"
#include "util.h"
#if !USE_LIBVMA
#define maybeconst const
#include "socket_fptr_t.h"
#else
#define maybeconst
#include "socket_fptr_t.h"
#if USE_LIBVMA == USE_LIBVMA_SERVER
#include <assert.h>
#include "smem.h"
#endif
#endif


/* ************************************************************************** *
 * Socket Function Definitions                                                *
 * ************************************************************************** */

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

// These types are defined in socket_fptr_t.h
#define DEFINE_SOCKPTR_STRUCT(fn) fn##_fptr_t fn;
struct socket_fptrs {
    SOCKET_FNS(DEFINE_SOCKPTR_STRUCT);
};


#if !USE_LIBVMA
/* ************************************************************************** *
 * Regular Sockets                                                            *
 * ************************************************************************** */

// Define s.fn to be the normal socket function
#define DEFINE_REGULAR_SOCKET_FN(fn) .fn = &fn,
static const struct socket_fptrs s = {
    SOCKET_FNS(DEFINE_REGULAR_SOCKET_FN)
};
static inline int init_vma_redirect() {
    return 0;
}


#elif USE_LIBVMA == USE_LIBVMA_LOCAL
/* ************************************************************************** *
 * Local libVMA                                                               *
 * ************************************************************************** */

// Define s.fn as pointers defined at run time (libVMA library calls)
extern struct socket_fptrs s;
pid_t original_fork(void);
pid_t vmafork(void);

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
    #undef DEFINE_LIBVMA_SOCKET_FN
    return 0;
}


#elif USE_LIBVMA == USE_LIBVMA_SERVER
/* ************************************************************************** *
 * Server libVMA                                                              *
 * ************************************************************************** */

// -- Declarations --

extern struct socket_fptrs s;

#define VMAS_COMMANDS(X) \
    X(socket) \
    X(setsockopt) \
    X(bind) \
    X(listen) \
    X(accept) \
    X(connect) \
    X(read) \
    X(write) \
    X(close)

#define NAME_LIST(N) vmas_cmd_ ## N,
enum vma_server_command { 
    VMAS_COMMANDS(NAME_LIST)
    vmas_cmd_quit
};
#undef NAME_LIST

enum vmas_command_state { 
    VMAS_STATE_REQUEST_SUBMITTED, 
    VMAS_STATE_RESPONSE_READY,
    VMAS_STATE_RESPONSE_CONSUMED  // means this request may be freed
};

struct vmas_smem_command {
    size_t size;  // size of entire structure
    struct vmas_smem_command *next;
    enum vma_server_command command;
    enum vmas_command_state state;
    long return_value;
    char data[VMA_SERVER_SMEM_SIZE];
};

/* The structure of the VMA Server Request Queue (a circular buffer) is as
   follows:

   |           |
   | free      |
   | space     | 
   |-----------|  head; start of list                  
   | answered  |     |                                |
   | queries   |     |  n_processed                   |
   |           |     .                                |
   |-----------|  next request not yet processed      |  n_submitted
   | to-be-    |                                      |
   | processed |                                      |
   | queries   |                                      .
   |-----------|  insert next request to be submitted here
   | free      |
   | space     |
   |           |
   */

struct vmas_smem_struct { 
    size_t head;
    size_t n_processed;
    size_t n_submitted;
    struct vmas_smem_command commands[VMA_SERVER_SMEM_SLOTS];
};


extern struct smem *vmas_smem;
#define vmas_smem_s ((struct vmas_smem_struct *)vmas_smem->data)

#define VMAS_LIST_IDX(idx) \
    ((idx) % VMA_SERVER_SMEM_SLOTS)

#define VMAS_LIST_AT(idx) \
    (vmas_smem_s->commands[VMAS_LIST_IDX(idx)])

// -- socket function signatures used to generate callbacks --

// socket(int domain, int type, int protocol)
#define VMAS_socket_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, domain) AND \
    IMM(int, type) AND \
    IMM(int, protocol)

// setsockopt(int socket, int level, int option_name, void *option_value, 
//            socklen_t option_len)
#define VMAS_setsockopt_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, socket) AND \
    IMM(int, level) AND \
    IMM(int, option_name) AND \
    RPTR(char, MAXLEN, option_len, option_value) AND \
    IMM(socklen_t, option_len)

// bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
#define VMAS_bind_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, sockfd) AND \
    RPTR(struct sockaddr, sizeof(struct sockaddr), addrlen, addr) AND \
    IMM(socklen_t, addrlen)

// listen(int sockfd, int backlog)
#define VMAS_listen_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, sockfd) AND \
    IMM(int, backlog)

// accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
#define VMAS_accept_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, sockfd) AND \
    WPTR(struct sockaddr, sizeof(struct sockaddr), *addrlen, addr) AND \
    RWPTR(socklen_t, sizeof(socklen_t), sizeof(socklen_t), addrlen)

// connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
#define VMAS_connect_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, sockfd) AND \
    RPTR(struct sockaddr, sizeof(struct sockaddr), addrlen, addr) AND \
    IMM(socklen_t, addrlen)

// read(int fd, char *buf, size_t count)
#define VMAS_read_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, fd) AND \
    WPTR(char, MAXLEN, count, buf) AND \
    IMM(size_t, count)

// write(int fd, char *buf, size_t count)
#define VMAS_write_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, fd) AND \
    RPTR(char, MAXLEN, count, buf) AND \
    IMM(size_t, count)

// close(int fd)
#define VMAS_close_ARGS(IMM, RPTR, WPTR, RWPTR, AND) \
    IMM(int, fd)

// -- server callback functions and structures --

#define MAXLEN VMA_SERVER_SMEM_SIZE
#define COMMA() ,
#define NOTHING
#define IGNORE(...) 

// structs vmas_XXX_args
#define ARG_STRUCT_IMM(T, N) T N;
#define ARG_STRUCT_PTR(T, L_static, L_dynamic, N) T N[L_static];
#define DEF_ARG_STRUCT(NAME) \
    struct vmas_ ## NAME ## _args {\
        VMAS_ ## NAME ## _ARGS(ARG_STRUCT_IMM, \
                               ARG_STRUCT_PTR, \
                               ARG_STRUCT_PTR, \
                               ARG_STRUCT_PTR, \
                               NOTHING) \
    };

VMAS_COMMANDS(DEF_ARG_STRUCT)

#undef ARG_STRUCT_IMM
#undef ARG_STRUCT_PTR
#undef DEF_ARG_STRUCT

#define ARG_LIST_IMM(T, N) T N
#define ARG_LIST_PTR(T, L_static, L_dynamic, N) T *N

// functions size_t vmas_req_async_submit
// submit a socket function request to the VMA server but do not block for its
// result; an index is returned that can be used to retrieve the results later
// with the vmas_req_async_await functions
#define DEF_REQ_FUN_ASYNC_SUBMIT(NAME) \
    size_t vmas_req_async_submit_ ## NAME( \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, ARG_LIST_PTR, ARG_LIST_PTR, \
                                   ARG_LIST_PTR, COMMA()));
VMAS_COMMANDS(DEF_REQ_FUN_ASYNC_SUBMIT)

// functions int vmas_req_async_await
// wait for the results from a previous asynchronous socket function request
#define DEF_REQ_FUN_ASYNC_AWAIT(NAME) \
    int vmas_req_async_await_ ## NAME(\
            size_t head, \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, ARG_LIST_PTR, ARG_LIST_PTR, \
                                   ARG_LIST_PTR, COMMA()));
VMAS_COMMANDS(DEF_REQ_FUN_ASYNC_AWAIT)

// functions int vmas_req_XXX(args ...)
// these replace the actual socket functions in the client, such as read(),
// socket() etc. with a callback to the server process
#define DEF_REQ_FUN(NAME) \
    int vmas_req_ ## NAME(VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, \
                                                 ARG_LIST_PTR, \
                                                 ARG_LIST_PTR, \
                                                 ARG_LIST_PTR, \
                                                 COMMA()));
VMAS_COMMANDS(DEF_REQ_FUN)

#undef ARG_LIST_IMM
#undef ARG_LIST_PTR
#undef DEF_REQ_FUN_ASYNC_SUBMIT
#undef DEF_REQ_FUN_ASYNC_AWAIT
#undef DEF_REQ_FUN

#undef MAXLEN
#undef COMMA
#undef NOTHING
#undef IGNORE

// -- init_vma_redirect - Starts the Server --

static inline int init_vma_redirect() {
    if(NULL != s.socket) {
        // Already initialized.
        return 0;
    }
#if USE_LIBVMA == USE_LIBVMA_SERVER
    char smem_name[255];
    snprintf(smem_name, sizeof(smem_name), "/vmas_smem_%d", getpid());
    SAFE_Z_TRY(vmas_smem = smem_init_named(sizeof(struct vmas_smem_struct),
                                           smem_name));
    vmas_smem_s->head = 0;
    vmas_smem_s->n_processed = 0;
    vmas_smem_s->n_submitted = 0;
    if(0 == fork()) {
        /* Child; set socket functions up to just call back to parent via
          shared memory */
        #define DEFINE_VMAS_CLIENT_SOCKET_FN(fn) s.fn = \
            (fn##_fptr_t)&vmas_req_ ## fn;
        VMAS_COMMANDS(DEFINE_VMAS_CLIENT_SOCKET_FN);
        return 0;
    } else {
        /* Parent: This is the server handling the requests. */
        char * const args[] = { "vma-server", smem_name, NULL };
        setenv("LD_PRELOAD", "/usr/lib/libvma.so", 1);
        LZ_TRY_EXCEPT(execvp("vma-server", args),
                      exit(1));
    }
#endif
#if USE_LIBVMA == USE_LIBVMA_LOCAL
    void *handle = NULL;
    Z_TRY(handle = dlopen("/usr/lib/libvma.so", RTLD_NOW));
    #define DEFINE_LIBVMA_SOCKET_FN(fn) s.fn = (fn##_fptr_t)\
                            dlsym(handle, #fn);
    SOCKET_FNS(DEFINE_LIBVMA_SOCKET_FN);
#endif
    return 0;
}

#endif

#endif