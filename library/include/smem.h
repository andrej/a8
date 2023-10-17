#ifndef SMEM_H
#define SMEM_H

#include <sys/mman.h>
#include <semaphore.h>
#include "util.h"
struct smem {
	sem_t sem;
	size_t len;
	volatile char data[];
};

#define mem_barrier asm volatile ("" : : : "memory")

#define smem_get(smem, T, get_expr) ({ \
	volatile T val = 0; \
	while(0 != unprotected_funcs.sem_wait(&(smem)->sem)); \
	mem_barrier; \
	val = (get_expr); \
	mem_barrier; \
	unprotected_funcs.sem_post(&(smem)->sem); \
	val; \
})

#define smem_put(smem, put_op) ({ \
	while(0 != unprotected_funcs.sem_wait(&(smem)->sem)); \
	mem_barrier; \
	put_op; \
	mem_barrier; \
	unprotected_funcs.sem_post(&(smem)->sem); \
})

#define smem_await(cond) ({ \
	while((cond)) { \
 		sched_yield(); \
		mem_barrier; \
	} \
})

#define smem_total_len(len) \
	(((len) + sizeof(struct smem) + monmod_page_size - 1) \
	 & ~(monmod_page_size - 1))

static struct smem *smem_init(size_t len)
{
	struct smem *smem = NULL;
	const size_t total_len = smem_total_len(len);
	Z_TRY_EXCEPT(smem = mmap(NULL, 
	                         total_len, 
	                         PROT_READ | PROT_WRITE,
	                         MAP_SHARED | MAP_ANONYMOUS, 
							 -1, 
							 0),
				 return NULL);
	memset(smem, 0, len);
	smem->len = len;
	NZ_TRY_EXCEPT(sem_init(&smem->sem, 1, 1),
	              goto abort);
	return smem;
abort:
	munmap(smem, total_len);
	return NULL;
}

static void smem_free(struct smem *smem)
{
	sem_destroy(&smem->sem);
	munmap(smem, smem_total_len(smem->len));
}

#endif