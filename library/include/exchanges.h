#ifndef EXCHANGES_H
#define EXCHANGES_H

/**
 * Contains all functionality concerned with replicating and cross-checking
 * system call arguments and return values.
 * 
 * Anything that conducts network exchanges at a macro level, essentially our
 * network protocol, should go in this file.
 */

#include <stdbool.h>
#include "exchange_types.h"
#include "util.h"
#include "arch.h"
#include "serialization.h"
#include "communication.h"
#include "handlers.h"
#include "monitor.h"

/**
 * After calling this function, all monitors are at the same point
 *  in code and network buffers are empty. 
 *  
 *  These are the types of divergences:
 *  1. Everyone wants to do cross-checking, and they disagree -- easiest case.
 *  2. Follower enters cross-checking while leader sends out replication buffer.
 *  3. Follower awaits replication buffer while leader wants to do 
 *     cross-checking.
 *  4. Follower receives replication buffer, but it is not for the same system
 *     calls it has issued. This can only happen for non-cross-checked system
 *     calls (otherwise, step 1 or 2 would happen). We just let execution
 *     continue with the "garbage" data and catch it at cross-checking later.
 *
 *  The follower will always detect divergences first, because it is the one
 *  catching up. 
 **/
int synchronize(struct monitor *monitor, msg_type_t reason);

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
int cross_check_args(struct monitor *monitor,
                     struct syscall_info *canonical);

void log_args(char *buf, size_t max_len, 
              struct syscall_info *actual,
              struct syscall_info *canonical);

int replication_init(struct monitor * const monitor, size_t flush_after);

void replication_destroy(struct monitor *monitor);

int replicate_results(struct monitor *monitor,
                      struct syscall_info *canonical);


#endif