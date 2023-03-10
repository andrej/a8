#ifndef BATCHED_COMMUNICATION_H
#define BATCHED_COMMUNICATION_H

#include <unistd.h>
#include <stdbool.h>
#include "communication.h"


/* ************************************************************************** *
 * Data Types                                                                 *
 * ************************************************************************** */

struct __attribute__((packed)) batch_item {  // sent over network
	uint64_t length;  // length of contents[] in bytes
	char contents[];
};

struct __attribute__((packed)) batch {  // sent over network
	uint64_t length;  // length of items[] in bytes
	uint64_t capacity;  // capacity of items[] in bytes
	struct batch_item items[];
};

struct batch_communicator {
	const struct communicator *comm;
	const struct peer *recv_peer; /* peer to receive from; 
	                                 for sender, data is broadcast to all */
	size_t capacity;
	size_t flush_after;
	struct batch *current_batch;
	struct batch_item *current_item;  /* next not-yet-consumed item inside 
	                               current_batch (in receiver);
				       next free item (in sender usually);
				       reserved item to-be-sent (in sender after
				       batch_comm_reserve but before 
				       batch_comm_broadcast_reserved call) */
	struct batch preallocated_batch;
};


/* ************************************************************************** *
 * API Funtions                                                               *
 * ************************************************************************** */

struct batch_communicator *init_batch_comm(const struct communicator *comm, 
                                           const struct peer *recv_peer,
                                           size_t capacity,
					   size_t flush_after);

void free_batch_comm(struct batch_communicator *bc);

char *batch_comm_receive(struct batch_communicator *bc, size_t *n);

/**
 * If the current batch has contents, broadcst it to the receivers, then free 
 * it. This must be called only on the sender side before any non-batched
 * communication takes place. (Otherwise, receivers waiting for a batch will
 * receive other message instead of batch first.)
 */
int batch_comm_flush(struct batch_communicator *bc);

/**
 * Reserve `len` bytes, to be subsequently sent using 
 * `batch_comm_broadcast_reserved` (as part of the next batch). May broadcast
 * the current batch to recipients if adding `len` bytes would overflow the
 * current batch capacity. After a successful call, you can write up to `len`
 * bytes to the returned pointer -- those bytes will be sent at the next
 * batch_comm_broadcast_reserved call. Such a call *must* always follow a
 * call to this function.
 */
char *batch_comm_reserve(struct batch_communicator *bc, size_t len);

int batch_comm_broadcast_reserved(struct batch_communicator *bc);

void batch_comm_cancel_reserved(struct batch_communicator *bc);

#endif