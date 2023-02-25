#ifndef REPLICATION_H
#define REPLICATION_H

/**
 * Contains all functionality concerned with replicating and cross-checking
 * system call arguments and return values.
 */

#include <stdbool.h>
#include "util.h"
#include "arch.h"
#include "serialization.h"
#include "communication.h"
#include "handlers.h"
#include "environment.h"

/**
 * Compare serialized arguments in `canonical` with other instances. This may
 * also flush batched replication buffers, so follower nodes waiting on
 * replication information can "catch up" with leader before cross-checking
 * takes palce.
 * 
 * A return value of 1 indicates that all nodes agree -- no divergence.
 * A return value of 0 indicates a divergence.
 * A negative return value indicates an error, such as network communication
 * error, during cross-checking.
 */
int cross_check_args(struct environment *env,
                     struct syscall_info *canonical);

void log_args(char *buf, size_t max_len, 
              struct syscall_info *actual,
              struct syscall_info *canonical);

int init_replication(struct environment *env, size_t size);

void free_replication();

int replicate_results(struct environment *env,
                      struct syscall_info *canonical,
                      bool force_send);


#endif