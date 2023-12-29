#ifndef BATCHED_COMMUNICATION_H
#define BATCHED_COMMUNICATION_H

#include <unistd.h>
#include <stdbool.h>
#include "communication.h"

/* ************************************************************************** *
 * Macros                                                                     *
 * ************************************************************************** */

#define batch_end(b) ((struct batch_item *)((char *)(b)->items \
                                           + (b)->length))
#define batch_capacity_end(b) ((struct batch_item *)((char *)(b)->items \
                                                     + (b)->capacity))
#define next_item(i) ((struct batch_item *)((char *)(i) \
                                            + sizeof(*i) \
                                            + (i)->length))


/* ************************************************************************** *
 * Data Types                                                                 *
 * ************************************************************************** */

struct __attribute__((packed)) batch_item {  // sent over network
	uint32_t length;  // length of contents[] in bytes
	char contents[];
};

struct __attribute__((packed)) batch {  // sent over network
	uint32_t length;  // length of items[] in bytes
	uint32_t capacity;  // capacity of items[] in bytes
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
	struct batch *preallocated_batch;
};


/* ************************************************************************** *
 * API Funtions                                                               *
 * ************************************************************************** */

struct batch_communicator *init_batch_comm(const struct communicator *comm, 
                                           const struct peer *recv_peer,
                                           size_t capacity,
					   size_t flush_after);

int init_batch_comm_at(struct batch_communicator *bc,
                       char *preallocated_memory,
                       const struct communicator *comm, 
                       const struct peer *recv_peer,
                       size_t capacity,
                       size_t flush_after);

void free_batch_comm(struct batch_communicator *bc);

static inline bool 
batch_comm_receive_will_communicate(const struct batch_communicator * const bc)
{
	return bc->current_item >= batch_end(bc->current_batch);
}

char *batch_comm_receive(struct batch_communicator *bc, size_t *n);

static inline bool 
batch_comm_flush_will_communicate(struct batch_communicator *bc)
{
	return bc->current_batch->length > 0;
}

/**
 * If the current batch has contents, broadcst it to the receivers, then free 
 * it. This must be called only on the sender side before any non-batched
 * communication takes place. (Otherwise, receivers waiting for a batch will
 * receive other message instead of batch first.)
 */
int batch_comm_flush(struct batch_communicator *bc);

static inline bool
batch_comm_reserve_will_communicate(const struct batch_communicator * const bc,
                                    size_t len)
{
	const size_t item_len = sizeof(*bc->current_item) + len; 
	struct batch *b = bc->current_batch;
	return ((char*)bc->current_item + item_len 
	        > (char*)batch_capacity_end(b));
}

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

static inline bool
batch_comm_broadcast_reserved_will_communicate(const struct batch_communicator 
                                               * const bc)
{
	return (bc->current_batch->length >= bc->flush_after
	        || bc->current_item >= batch_capacity_end(bc->current_batch));
}

int batch_comm_broadcast_reserved(struct batch_communicator *bc);

void batch_comm_cancel_reserved(struct batch_communicator *bc);

#endif