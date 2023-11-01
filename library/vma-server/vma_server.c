#define NO_UNPROTECTED
#include "build_config.h"
#undef USE_LIBVMA
#define USE_LIBVMA USE_LIBVMA_SERVER
#include <unistd.h>
#include "vma_redirect.h"

#define MAXLEN (VMA_SERVER_SMEM_SIZE/4)
#define COMMA() ,

// functions static inline int vmas_do_XXX(char *reqbuf)
// These functions get called on the server side process to execute the actual
// socket function and write back the result, inside of vma_server_main().
#define DEF_DO_FUN_ARG_LIST_IMM(T, N) \
	((argstruct_t *)reqbuf)->N
#define DEF_DO_FUN_ARG_LIST_PTR(T, L_static, L_dynamic, N)  \
	((argstruct_t *)reqbuf)->N
#define DEF_DO_FUN(NAME) \
	static inline int \
	vmas_do_ ## NAME(char *reqbuf) { \
		typedef struct vmas_ ## NAME ## _args argstruct_t; \
		return NAME(VMAS_ ## NAME ## _ARGS(DEF_DO_FUN_ARG_LIST_IMM, \
		                                   DEF_DO_FUN_ARG_LIST_PTR, \
                                                 DEF_DO_FUN_ARG_LIST_PTR, \
		                                   DEF_DO_FUN_ARG_LIST_PTR, \
	                                          COMMA())); \
	}

VMAS_COMMANDS(DEF_DO_FUN)

#undef DEF_DO_FUN_ARG_LIST_IMM
#undef DEF_DO_FUN_ARG_LIST_PTR
#undef DEF_DO_FUN

size_t monmod_page_size = 0;
struct smem *vmas_smem;

int vma_server_main();

int main(int argc, char **argv)
{
       assert(argc == 2); // usage: vma-server <smem-name>
       monmod_page_size = sysconf(_SC_PAGE_SIZE);
       Z_TRY_EXCEPT(vmas_smem = smem_open_named(sizeof(struct vmas_smem_struct), 
                                                argv[1]),
                    goto abort);
       shm_unlink(argv[1]);
       vma_server_main();
       return 0;
abort:
       shm_unlink(argv[1]);
       return 1;
}

#define VMAS_DISPATCH(NAME) \
	case vmas_cmd_ ## NAME: \
		return vmas_do_ ## NAME (smem->data);
static int vmas_dispatch(struct vmas_smem_struct *smem)
{
	switch(smem->command) {
		VMAS_COMMANDS(VMAS_DISPATCH)
		default:
			printf("Unknown command to VMA server: %d\n", 
                            (int)smem->command);
			exit(1);
	}
	return -1; // unreachable
}
#undef VMAS_DISPATCH

int vma_server_main()
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