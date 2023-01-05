#ifndef REPLICATION_H
#define REPLICATION_H

/**
 * Contains all functionality concerned with replicating and cross-checking
 * system call arguments and return values.
 */

#include "util.h"
#include "arch.h"
#include "serialization.h"
#include "communication.h"
#include "handlers.h"
#include "environment.h"

/* We cannot use dynamic memory allocation routines (malloc/calloc) in system
   call handler code, since they are non-reentrant. For example, calling 
   malloc() inside the `brk` handler can cause a deadlock, because the `brk`
   system call may have been issued by another malloc() call that is still 
   holding a lock, leading to deadlock. Therefore, instead, we use fixed-size
   previously allocated buffers. */
#define REPLICATION_BUFFER_SZ 4096
extern char replication_buffer[REPLICATION_BUFFER_SZ];

int cross_check_args(struct environment *env,
                     struct syscall_info *canonical);

char *serialize_args(size_t *len, struct syscall_info *canonical);
void log_args(char *buf, size_t max_len, 
              struct syscall_info *actual,
              struct syscall_info *canonical);

int replicate_results(struct environment *env,
                      struct syscall_info *canonical);

char *get_replication_buffer(struct syscall_info *canonical,
			     size_t *replication_buf_len);

int write_back_replication_buffer(struct syscall_info *canonical,
				  char *replication_buf,
				  size_t replication_buf_len);

#endif