#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <link.h>
#include <elf.h>

#include "syscall.h"
#include "util.h"

void *safe_malloc(size_t size)
{
#if ENABLE_SAFE_MALLOC
	const long ret = monmod_trusted_syscall(
		__NR_mmap, 0, size, (long)(PROT_READ | PROT_WRITE),
		(long)(MAP_PRIVATE | MAP_ANONYMOUS), 0, 0);
	if(0 > ret) {
		return NULL;
	}
	return (void *)ret;
#else
	SAFE_WARNF("safe_malloc is disabled, but a memory request for " \
	           "%lu bytes was issued. Enable safe_malloc, or use/increase "\
		   "preallocated buffers.\n", size);
	return NULL;
#endif
}

void safe_free(void *ptr, size_t size)
{
#if ENABLE_SAFE_MALLOC
	const int ret = monmod_trusted_syscall(
		SYS_munmap, (long)ptr, (long)size, 0, 0, 0, 0);
	if(0 > ret) {
		SAFE_WARNF("Failed to free memory at %p, length %lx.\n",
		          ptr, size);
		exit(1);
	}
#else
	SAFE_WARNF("Tried to free pointer %p (size %lu), even though "
	           "safe_malloc is disabled.\n", ptr, size);
	exit(1);
#endif
}

struct _find_mapped_region_bounds_data {
	void * const search_addr;
	void *start;
	size_t len;
};

static int _find_mapped_region_bounds_cb(struct dl_phdr_info *info, size_t size,
                                         void *data)
{
	void *addr = NULL;
	struct _find_mapped_region_bounds_data *d = 
		(struct _find_mapped_region_bounds_data *)data;
	for(size_t i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *phdr_info = &info->dlpi_phdr[i];
		if(PT_LOAD != phdr_info->p_type) {
			// Only consider loadable segments
			continue;
		}
		// see man dl_iterate_phdr
		addr = (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);	
		if(addr <= d->search_addr 
		   && d->search_addr < addr + phdr_info->p_memsz) {
			d->start = addr;
			d->len = (size_t)phdr_info->p_memsz;
			return 1;
		}
	}
	return 0;
}

/**
 * Puts the start and end address of the shared library that the address needle
 * is a part of in `start` and `end`. Returns 1 if this functions address is not
 * within the range of any loaded library (0 on success).
 */
int find_mapped_region_bounds(void * const needle, 
                              void **start, size_t *len)
{
	int ret = 0;
	struct _find_mapped_region_bounds_data d = { needle, NULL, 0 };
	ret = !(1 == dl_iterate_phdr(_find_mapped_region_bounds_cb, &d));
	*start = d.start;
	*len = d.len;
	return ret;
}
