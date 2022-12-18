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

bool cross_check_args(struct environment *env,
                      struct normalized_args *normalized_args);

char *serialize_args(size_t *len, struct normalized_args *normalized_args);
void log_args(char *buf, size_t max_len, 
              struct normalized_args *normalized_args);

int normalize_args(struct environment *env,
                   const struct syscall_handler *handler,
                   struct normalized_args *normalized_args,
                   long args[N_SYSCALL_ARGS]);

int replicate_results(struct environment *env,
                      struct normalized_args *normalized_args,
                      long args[N_SYSCALL_ARGS],
                      long *ret);

char *get_replication_buffer(struct normalized_args *normalized_args,
                             long args[N_SYSCALL_ARGS],
                             long *ret,
			     size_t *replication_buf_len);

int write_back_replication_buffer(char *replication_buf,
                                  size_t replication_buf_len,
                                  struct normalized_args *normalized_args,
                                  long args[N_SYSCALL_ARGS],
                                  long *ret);

#endif