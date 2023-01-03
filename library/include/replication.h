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