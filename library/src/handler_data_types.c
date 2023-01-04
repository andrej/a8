#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include "handler_data_types.h"


/* --------------------------------------------------------------------------
    struct stat normalization
    
           Offset / Size  ARM64  x86_64
               sizeof(s)    128     144
                s.st_dev      0       0  
        sizeof(s.st_dev)      8       8  
                s.st_ino      8       8  
        sizeof(s.st_ino)      8       8  
               s.st_mode     16      24 
       sizeof(s.st_mode)      4       4  
              s.st_nlink     20      16 
      sizeof(s.st_nlink)      4       8  
                s.st_uid     24      28 
        sizeof(s.st_uid)      4       4  
                s.st_gid     28      32 
        sizeof(s.st_gid)      4       4  
               s.st_rdev     32      40 
       sizeof(s.st_rdev)      8       8  
               s.st_size     48      48 
       sizeof(s.st_size)      8       8  
            s.st_blksize     56      56 
    sizeof(s.st_blksize)      4       8  
             s.st_blocks     64      64 
     sizeof(s.st_blocks)      8       8  
               s.st_atim     72      72 
       sizeof(s.st_atim)     16      16 
               s.st_mtim     88      88 
       sizeof(s.st_mtim)     16      16 
               s.st_ctim    104     104
       sizeof(s.st_ctim)     16      16 
   -------------------------------------------------------------------------- */

char *normalize_stat_struct_into(struct stat *d, char *n)
{
	memset(n, 0, NORMALIZED_STAT_STRUCT_SIZE);
	// TODO Handle endianness
	memcpy(n +   0, &d->st_dev,      8);
	memcpy(n +   8, &d->st_ino,      8);
	memcpy(n +  16, &d->st_mode,     4);
	memcpy(n +  20, &d->st_nlink,    8);
	memcpy(n +  28, &d->st_uid,      4);
	memcpy(n +  32, &d->st_gid,      4);
	memcpy(n +  36, &d->st_rdev,     8);
	memcpy(n +  44, &d->st_size,     8);
	memcpy(n +  52, &d->st_blksize,  8);
	memcpy(n +  60, &d->st_blocks,   8);
	memcpy(n +  68, &d->st_atim + 0, 8);
	memcpy(n +  76, &d->st_atim + 8, 8);
	memcpy(n +  84, &d->st_mtim + 0, 8);
	memcpy(n +  92, &d->st_mtim + 8, 8);
	memcpy(n + 100, &d->st_ctim + 0, 8);
	memcpy(n + 108, &d->st_ctim + 8, 8);
	return n;
}

void denormalize_stat_struct_into(char *n, struct stat *d)
{
	memset(d, 0, sizeof(struct stat));
	// TODO Handle endianness
	// We assume little endian here, so that narrowing conversions (kind of)
	// work, i.e. small enough values should remain the same when we chop
	// off larger address values.
	d->st_dev      =   *(dev_t *)           (n +   0);
	d->st_ino      =   *(ino_t *)           (n +   8);
	d->st_mode     =   *(mode_t *)          (n +  16);
	d->st_nlink    =   *(nlink_t *)         (n +  20);
	d->st_uid      =   *(uid_t *)           (n +  28);
	d->st_gid      =   *(gid_t *)           (n +  32);
	d->st_rdev     =   *(dev_t *)           (n +  36);
	d->st_size     =   *(off_t *)           (n +  44);
	d->st_blksize  =   *(blksize_t *)       (n +  52);
	d->st_blocks   =   *(blkcnt_t *)        (n +  60);
	d->st_atim     =   *(struct timespec *) (n +  68);
	d->st_mtim     =   *(struct timespec *) (n +  84);
	d->st_ctim     =   *(struct timespec *) (n + 100);
}

/* --------------------------------------------------------------------------
    struct epoll_event normalization
    On aarch64, sizeof(struct epoll_event) == 16; offset of data == 8
    On x86_64,  sizeof(struct epoll_event) == 12; offset of data == 4
   -------------------------------------------------------------------------- */
size_t normalize_epoll_event_structs_into(size_t num, struct epoll_event *d, 
                                          char *n)
{
	memset(n, 0, NORMALIZED_EPOLL_EVENT_SIZE);
	for(size_t i = 0; i < num; i ++) {
		*(uint32_t *)    &n[16*i + 0] = d[i].events;
		*(epoll_data_t *)&n[16*i + 8] = d[i].data;
	}
	return num * NORMALIZED_EPOLL_EVENT_SIZE;
}

void denormalize_epoll_event_structs_into(size_t num, 
                                          const char *n,
                                          struct epoll_event *d)
{
	memset(d, 0, sizeof(struct epoll_event));
	for(size_t i = 0; i < num; i++) {
		d[i].events = *(uint32_t *)    &n[16*i + 0];
		d[i].data   = *(epoll_data_t *)&n[16*i + 8];
	}
}
