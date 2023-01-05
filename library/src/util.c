#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include "syscall.h"
#include "util.h"

void *safe_malloc(size_t size)
{
	const long ret = monmod_trusted_syscall(
		__NR_mmap, 0, size, (long)(PROT_READ | PROT_WRITE),
		(long)(MAP_PRIVATE | MAP_ANONYMOUS), 0, 0);
	if(0 > ret) {
		return NULL;
	}
	return (void *)ret;
}

void safe_free(void *ptr, size_t size)
{
	const int ret = monmod_trusted_syscall(
		SYS_munmap, (long)ptr, (long)size, 0, 0, 0, 0);
	if(0 > ret) {
		SAFE_LOGF(log_fd, "Failed to free memory at %p, length %lx.\n",
		          ptr, size);
		exit(1);
	}
}
