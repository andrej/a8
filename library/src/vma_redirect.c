#define _GNU_SOURCE
#include <dlfcn.h>
#include "build_config.h"

#if USE_LIBVMA

#include <unistd.h>
#include "vma_redirect.h"
#include "unprotected.h"
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
__attribute((visibility("default"),
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

int vma_server_main(struct smem *vmas_smem)
{
       while(1) {
              // Wait for a request
              smem_lock_if(vmas_smem,
                           VMAS_STATE_REQUEST_SUBMITTED 
                           == vmas_smem_data->state);
              if(vmas_cmd_quit == vmas_smem_data->command) {
                     break;
              }
              vmas_smem_data->return_value = 
                     vmas_dispatch(vmas_smem_data);
              vmas_smem_data->state = VMAS_STATE_RESPONSE_READY;
              smem_unlock(vmas_smem);
       }
       return 0;
}

// functions static inline int vmas_req_XXX(args ...)
#define MAXLEN (VMA_SERVER_SMEM_SIZE/4)
#define COMMA() ,
#define NOTHING
#define IGNORE(...) 
#define DEF_REQ_FUN_ARG_LIST_IMM(T, N) T N
#define DEF_REQ_FUN_ARG_LIST_PTR(T, L_static, L_dynamic, N) T *N
#define DEF_REQ_FUN_WRITE_ARG_IMM(T, N) \
	((argstruct_t *)reqbuf)->N = N;
#define DEF_REQ_FUN_WRITE_ARG_PTR(T, L_static, L_dynamic, N) \
	assert(L_dynamic <= L_static); \
	if((void *)&((argstruct_t *)reqbuf)->N != (void *)N) { \
		memcpy(&((argstruct_t *)reqbuf)->N, N, sizeof(T) * L_dynamic); \
	}
#define DEF_REQ_FUN_READ_ARG_PTR(T, L_static, L_dynamic, N) \
	if(L_dynamic > 0 && (void *)&((argstruct_t *)reqbuf)->N != (void *)N) { \
		memcpy(N, &((argstruct_t *)reqbuf)->N, L_dynamic); \
	}
#define DEF_REQ_FUN(NAME) \
	int vmas_req_ ## NAME(VMAS_ ## NAME ## _ARGS(DEF_REQ_FUN_ARG_LIST_IMM, \
                                                    DEF_REQ_FUN_ARG_LIST_PTR, \
                                                    DEF_REQ_FUN_ARG_LIST_PTR, \
                                                    DEF_REQ_FUN_ARG_LIST_PTR, \
	                                             COMMA())) { \
		typedef struct vmas_ ## NAME ## _args argstruct_t; \
		int return_value = 0; \
		char *reqbuf = vmas_smem_data->data; \
		smem_lock_if(vmas_smem, VMAS_STATE_IDLE == vmas_smem_data->state); \
		/* Write arguments to request buffer. */ \
		vmas_smem_data->command = vmas_cmd_ ## NAME; \
		VMAS_ ## NAME ## _ARGS(DEF_REQ_FUN_WRITE_ARG_IMM, \
		                       DEF_REQ_FUN_WRITE_ARG_PTR, \
		                       IGNORE, \
                                     DEF_REQ_FUN_WRITE_ARG_PTR, \
		                       NOTHING) \
		vmas_smem_data->state = VMAS_STATE_REQUEST_SUBMITTED; \
		smem_unlock(vmas_smem); \
		smem_lock_if(vmas_smem, \
		             VMAS_STATE_RESPONSE_READY == vmas_smem_data->state); \
		/* Copy results from return buffers (if any). */ \
		VMAS_ ## NAME ## _ARGS(IGNORE, \
                                     IGNORE, \
                                     DEF_REQ_FUN_READ_ARG_PTR, \
                                     DEF_REQ_FUN_READ_ARG_PTR, \
		                       NOTHING) \
		return_value = vmas_smem_data->return_value; \
		vmas_smem_data->state = VMAS_STATE_IDLE; \
		smem_unlock(vmas_smem); \
		return return_value; \
	} 

VMAS_COMMANDS(DEF_REQ_FUN)

#endif 

#endif