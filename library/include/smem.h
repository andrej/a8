#ifndef SMEM_H
#define SMEM_H

struct smem {
	int lock;
	char data[];
};

static inline void smem_lock(struct smem *ptr);
static inline void smem_unlock(struct smem *ptr);

#endif