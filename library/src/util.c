#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <link.h>
#include <elf.h>
#include <fcntl.h>

#include "monmod_syscall.h"
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

int open_log_file(unsigned long maj, unsigned long min)
{
	char log_file_path[128];
	snprintf(log_file_path, sizeof(log_file_path), MONMOD_LOG_FILE,
	         maj, min);
	if(0 > (monmod_log_fd = open(log_file_path, O_WRONLY | O_APPEND 
	                             | O_CREAT | O_TRUNC, 0664)))
	{
		WARNF("unable to open log file at %s: %s\n",
		      log_file_path,
		      strerror(errno));
		return 1;
	}
	return 0;
}

int drop_privileges(void)
{
    gid_t gid;
    uid_t uid;

    // no need to "drop" the privileges that you don't have in the first place!
    if (getuid() != 0) {
        return 0;
    }

    // when your program is invoked with sudo, getuid() will return 0 and you
    // won't be able to drop your privileges
    if ((uid = getuid()) == 0) {
        const char *sudo_uid = getenv("SUDO_UID");
        if (sudo_uid == NULL) {
            printf("environment variable `SUDO_UID` not found\n");
            return -1;
        }
        errno = 0;
        uid = (uid_t) strtoll(sudo_uid, NULL, 10);
        if (errno != 0) {
            perror("under-/over-flow in converting `SUDO_UID` to integer");
            return -1;
        }
    }

    // again, in case your program is invoked using sudo
    if ((gid = getgid()) == 0) {
        const char *sudo_gid = getenv("SUDO_GID");
        if (sudo_gid == NULL) {
            printf("environment variable `SUDO_GID` not found\n");
            return -1;
        }
        errno = 0;
        gid = (gid_t) strtoll(sudo_gid, NULL, 10);
        if (errno != 0) {
            perror("under-/over-flow in converting `SUDO_GID` to integer");
            return -1;
        }
    }

    if (setgid(gid) != 0) {
        perror("setgid");
        return -1;
    }
    if (setuid(uid) != 0) {
        perror("setgid");
        return -1;    
    }

    // check if we successfully dropped the root privileges
    if (setuid(0) == 0 || seteuid(0) == 0) {
        printf("could not drop root privileges!\n");
        return -1;
    }

    return 0;	
}
