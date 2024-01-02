#ifndef SMEM_H
#define SMEM_H

#include <sys/mman.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "util.h"
#include "unprotected.h"
struct smem {
	sem_t sem;
	size_t len;
	volatile char data[];
};

#define mem_barrier asm volatile ("" : : : "memory")

#define smem_lock(smem) ({ \
	while(0 != sem_wait(&(smem)->sem)); \
	mem_barrier; \
})

#define smem_lock_if(smem, cond) ({ \
	while(1) { \
		/* Do racy test without locking. */ \
		if(cond) { \
			/* Test was racy, now test properly that condition holds. */ \
			smem_lock(smem); \
			if(cond) { \
				break; \
			} \
			smem_unlock(smem); \
		} \
		mem_barrier; \
	} \
})

#define smem_unlock(smem) ({ \
	mem_barrier; \
	sem_post(&(smem)->sem); \
})

#define smem_get(smem, T, get_expr) ({ \
	volatile T val = 0; \
	smem_lock(smem); \
	val = (get_expr); \
	smem_unlock(smem); \
	val; \
})

#define smem_put(smem, put_op) ({ \
	smem_lock(smem); \
	put_op; \
	smem_unlock(smem); \
})

// use smem_get inside the cond of smem_await
#define smem_await(cond) ({ \
	while((cond)) { \
 		sched_yield(); \
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

static struct smem *smem_init_named(size_t len, const char *path)
{
	struct smem *smem = NULL;
	const size_t total_len = smem_total_len(len);
	int fd;
	LZ_TRY_EXCEPT(fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600),
	             return NULL);
	LZ_TRY_EXCEPT(ftruncate(fd, total_len), goto abort1);
	Z_TRY_EXCEPT(smem = mmap(NULL,
	                         total_len,
							 PROT_READ | PROT_WRITE,
							 MAP_SHARED,
							 fd,
							 0),
				 goto abort1);
	memset(smem, 0, len);
	smem->len = len;
	NZ_TRY_EXCEPT(sem_init(&smem->sem, 1, 1),
	              goto abort2);
	return smem;
abort2:
	munmap(smem, total_len);
	// fallthrough
abort1:
	shm_unlink(path);
	return NULL;
}

static struct smem *smem_open_named(size_t len, const char *path)
{
	struct smem *smem = NULL;
	const size_t total_len = smem_total_len(len);
	int fd;
	LZ_TRY_EXCEPT(fd = shm_open(path, O_RDWR, 0),
	              return NULL);
	Z_TRY_EXCEPT(smem = mmap(NULL,
	                         total_len,
							 PROT_READ | PROT_WRITE,
							 MAP_SHARED,
							 fd,
							 0),
				 goto abort);
	assert(smem->len == len);
	return smem;
abort:
	close(fd);
	return NULL;
}

/**
 * Use this type for atomic longs.
 */
typedef volatile unsigned long atomic_ulong_t;

/**
 * Atomically read bit N of L.
 */
static inline void atomic_set_bit(atomic_ulong_t *L, int N)
{
	unsigned long old_L;
	const unsigned long bitmask = 1UL << N;
	mem_barrier;
	old_L = __atomic_fetch_or(L, bitmask, __ATOMIC_SEQ_CST);
}

/**
 * Atomically wait for bit N of L to be 1 and simultaneously clear it. With
 * multiple racing threads calling this function, only one thread will see the
 * bit being set once.
 */
static inline void atomic_wait_and_clear_bit(atomic_ulong_t *L, int N)
{
	unsigned long old_L;
	const unsigned long bitmask = 1UL << N;
	do {
		mem_barrier;
		while((unsigned long)(*L & bitmask) == 0UL);  // Cheap, racy check first
		old_L = __atomic_fetch_and(L, ~bitmask, __ATOMIC_SEQ_CST);
	} while((unsigned long)(old_L & bitmask) == 0UL); 
		// somebody else simultaneously cleared bit,
	    // try again to wait for another set bit
}


#endif