#define _GNU_SOURCE
#include <dlfcn.h>
#include "build_config.h"

#if USE_LIBVMA

#include <unistd.h>
#include "vma_redirect.h"
#include "smem.h"

struct socket_fptrs s = {};

#if USE_LIBVMA == USE_LIBVMA_LOCAL

#include <unistd.h>
#include "vma_redirect.h"
#include "unprotected.h"
#include "smem.h"

pid_t
__attribute__((visibility("default"),
               section("unprotected")))
fork(void)
{
       return unprotected_funcs.syscall(__NR_monmod_fake_fork, 0,
                                        0, 0, 0, 0, 0);
}

pid_t
__attribute__((visibility("default"),
               section("unprotected")))
original_fork(void)
{
       pid_t (* _fork)() = dlsym(RTLD_NEXT, "fork");
       if(NULL == _fork) {
              exit(1);
       }
       return _fork();
}

pid_t
__attribute__((visibility("default"),
               section("unprotected")))
vmafork(void)
{
       return s.fork();
}

#endif

#if USE_LIBVMA == USE_LIBVMA_SERVER

struct smem *vmas_smem = NULL;

// functions static inline int vmas_req_XXX(args ...)
#define COMMA() ,
#define NOTHING
#define IGNORE(...) 
#define ARG_LIST_IMM(T, N) T N
#define ARG_LIST_PTR(T, L_static, L_dynamic, N) T *N
#define WRITE_ARG_IMM(T, N) \
    ((argstruct_t *)reqbuf)->N = N;
#define WRITE_ARG_PTR(T, L_static, L_dynamic, N) \
    assert(L_dynamic <= L_static); \
    if((void *)&((argstruct_t *)reqbuf)->N != (void *)N) { \
        memcpy(&((argstruct_t *)reqbuf)->N, N, sizeof(T) * L_dynamic); \
    }
#define READ_ARG_PTR(T, L_static, L_dynamic, N) \
    if(L_dynamic > 0 && (void *)&((argstruct_t *)reqbuf)->N != (void *)N) { \
        memcpy(N, &((argstruct_t *)reqbuf)->N, L_dynamic); \
    }
#define ARG_LIST_NAME_IMM(T, N) N
#define ARG_LIST_NAME(T, L_static, L_dynamic, N) N

/* Submit Request:
   1. Wait for free space in list.
   2. Put request at request_head.
   3. Increae request_head by added request_size.  */
#define DEF_REQ_FUN_ASYNC_SUBMIT(NAME) \
    size_t vmas_req_async_submit_ ## NAME( \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, ARG_LIST_PTR, ARG_LIST_PTR, \
                                   ARG_LIST_PTR, COMMA())) { \
        typedef struct vmas_ ## NAME ## _args argstruct_t; \
        /*assert(sizeof(argstruct_t) <= VMA_SERVER_SMEM_SIZE);*/ \
        /* Wait for a request slot to be available in the circular buffer. */ \
        const size_t i = vmas_smem_s->c_head; \
        atomic_wait_and_clear_bit(&vmas_smem_s->free, i); \
        struct vmas_smem_command * const req = &VMAS_LIST_AT(i); \
        char *reqbuf = req->data; \
        /* Write arguments to request buffer. */ \
        req->command = vmas_cmd_ ## NAME; \
        VMAS_ ## NAME ## _ARGS(WRITE_ARG_IMM, WRITE_ARG_PTR, IGNORE, \
                               WRITE_ARG_PTR, NOTHING) \
        /* Mark request submitted. */ \
        atomic_set_bit(&vmas_smem_s->submitted, i); \
        vmas_smem_s->c_head = VMAS_LIST_IDX(i + 1); \
        return i; \
    } 

/* Await request response from server:
   1. Wait for request at input "head" to be marked complete.
   2. Increase response_head if needed (remove prefix of completed requests).
      This may increase the response_head by ...
      ... one request, if the request we are waiting for is at response_head.
      ... no requests, if the request is not at response_head, and there are
          other requests further up in the list that are not complete yet.
      ... multiple requests, if the request we ware waiting for is at 
          response_head and some subsequent requests have already been 
          consumed as well.*/
#define DEF_REQ_FUN_ASYNC_AWAIT(NAME) \
    int vmas_req_async_await_ ## NAME(\
            size_t i, \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, ARG_LIST_PTR, ARG_LIST_PTR, \
                                   ARG_LIST_PTR, COMMA())) { \
        typedef struct vmas_ ## NAME ## _args argstruct_t; \
        struct vmas_smem_command * const req =  &VMAS_LIST_AT(i); \
        char *reqbuf = req->data; \
        int return_value = 0; \
        /* Wait for results to be ready. */ \
        atomic_wait_and_clear_bit(&vmas_smem_s->processed, i); \
        /* Copy results from return buffers (if any). */ \
        VMAS_ ## NAME ## _ARGS(IGNORE, IGNORE, READ_ARG_PTR, READ_ARG_PTR, \
                               NOTHING) \
        return_value = req->return_value; \
        /* Result consumed, free slot. */ \
        atomic_set_bit(&vmas_smem_s->free, i); \
        return return_value; \
    }

/* Async request and await response in one function to achieve blocking
   function call. */
#define DEF_REQ_FUN(NAME) \
    int vmas_req_ ## NAME(VMAS_ ## NAME ## _ARGS(ARG_LIST_IMM, \
                                                 ARG_LIST_PTR, \
                                                 ARG_LIST_PTR, \
                                                 ARG_LIST_PTR, \
                                                 COMMA())) { \
        size_t head = 0; \
        head = vmas_req_async_submit_ ## NAME( \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_NAME_IMM, ARG_LIST_NAME, \
                                   ARG_LIST_NAME, ARG_LIST_NAME, \
                                   COMMA())); \
        return vmas_req_async_await_ ## NAME(head, \
            VMAS_ ## NAME ## _ARGS(ARG_LIST_NAME_IMM, ARG_LIST_NAME, \
                                   ARG_LIST_NAME, ARG_LIST_NAME, \
                                   COMMA())); \
    }

VMAS_COMMANDS(DEF_REQ_FUN_ASYNC_SUBMIT)
VMAS_COMMANDS(DEF_REQ_FUN_ASYNC_AWAIT)
VMAS_COMMANDS(DEF_REQ_FUN)

#endif 

#endif