
#include "batched_communication.h"
#include "communication.h"
#include "util.h"

#define batch_end(b) ((struct batch_item *)((char *)(b)->items \
                                           + (b)->length))
#define batch_capacity_end(b) ((struct batch_item *)((char *)(b)->items \
                                                     + (b)->capacity))
#define next_item(i) ((struct batch_item *)((char *)(i) \
                                            + sizeof(*i) \
                                            + (i)->length))

struct batch_communicator *init_batch_comm(struct communicator *comm, 
                                           struct peer *recv_peer,
                                           size_t capacity,
					   size_t flush_after)
{
	struct batch_communicator *bc = NULL;
	Z_TRY_EXCEPT(bc = calloc(1, sizeof(*bc) + capacity),
	             return NULL);
	bc->comm = comm;
	bc->recv_peer = recv_peer;
	bc->flush_after = flush_after;
	bc->preallocated_batch.capacity = capacity;
	bc->preallocated_batch.length = 0;
	bc->current_batch = &bc->preallocated_batch;
	bc->current_item = bc->preallocated_batch.items;
	return bc;
}

static void free_current_batch(struct batch_communicator *bc)
{
	if(bc->current_batch != &bc->preallocated_batch)
	{
		safe_free(bc->current_batch,
		          sizeof(*bc->current_batch)+bc->current_batch->length);
		bc->current_batch = &bc->preallocated_batch;
	}
	bc->preallocated_batch.length = 0;
	bc->current_item = bc->preallocated_batch.items;
}

void free_batch_comm(struct batch_communicator *bc)
{
	free_current_batch(bc);
	free(bc);
}

/**
 * Sets bc->current_batch to a batch that can hold up to `len` bytes of items.
 * Precondition: bc->current_batch must have been freed previously.
 * If `len` is less than the default preallocated batch, the returned batch is
 * the prallocated batch. Otherwise, a oversized batch is allocated dynamically.
 */
static 
struct batch *alloc_current_batch(struct batch_communicator *bc, size_t len)
{
	SAFE_Z_TRY(bc->current_batch == &bc->preallocated_batch
	           && bc->preallocated_batch.length == 0);  // assert
	struct batch *b;
	if(len <= bc->preallocated_batch.capacity) {
		b = &bc->preallocated_batch;
		b->length = 0;
	} else {
		SAFE_Z_TRY(b = safe_malloc(sizeof(*bc->current_batch) + len));
		b->capacity = len;
		b->length = 0;
	}
	bc->current_batch = b;
	bc->current_item = bc->current_batch->items;
	return bc->current_batch;
}


/* ************************************************************************** *
 * Receive Functions                                                          *
 * ************************************************************************** */

static int receive_next_batch(struct batch_communicator *bc)
{
	free_current_batch(bc);

	struct message msg = {};
	size_t recv_len = 0;
	size_t items_len = 0;
	SAFE_NZ_TRY_EXCEPT(comm_receive_header(bc->comm, bc->recv_peer, &msg),
		           goto abort0);
	items_len = msg.length - sizeof(struct batch);
	recv_len = msg.length;
	
	/* Allocate new replication pool. */
	struct batch *b;
	SAFE_Z_TRY(b = alloc_current_batch(bc, items_len));
	/* TODO: If we received header of message, but not the body due to an
	   error, should call flush_fd here so later receives do not attempt to
	   read the body as the header of a new message. Currently terminates
	   on error. */

	SAFE_NZ_TRY_EXCEPT(comm_receive_body(bc->comm, bc->recv_peer, 
	                                     &msg, &recv_len, (char *)b),
		           goto abort1);
	SAFE_Z_TRY(msg.length == recv_len);  // assert
	SAFE_Z_TRY(b->length == items_len);

#if VERBOSITY >= 3
	SAFE_LOGF("! Batch of %ld bytes of replication information received.\n", 
	          items_len);
#endif

	return 0;

abort1:
	free_current_batch(bc);
abort0:
	return 1;
}

char *batch_comm_receive(struct batch_communicator *bc, size_t *n)
{
	char *ret = NULL;

	if(bc->current_item >= batch_end(bc->current_batch)) {
		/* Batch exhausted. Reset and receive next batch. */
		SAFE_NZ_TRY_EXCEPT(receive_next_batch(bc),
		                   return NULL);
	}

	/* Return a previously received item from the batch. */
	ret = bc->current_item->contents;
	*n = bc->current_item->length;
	bc->current_item = next_item(bc->current_item);
	return ret;
}


/* ************************************************************************** *
 * Send Functions                                                             *
 * ************************************************************************** */

int batch_comm_flush(struct batch_communicator *bc)
{
	if(bc->current_batch->length > 0) {
		const size_t bcast_len = bc->current_batch->length +
		                         sizeof(*bc->current_batch);
		SAFE_NZ_TRY_EXCEPT(comm_broadcast(bc->comm, bcast_len, 
		                                  (char *)bc->current_batch),
				   return 1);
#if VERBOSITY >= 3
		SAFE_LOGF("! Flushed batch of %ld bytes of previous syscall's "
		          "replication information.\n", 
			  bc->current_batch->length);
#endif
	}
	free_current_batch(bc);
	return 0;
}

char *batch_comm_reserve(struct batch_communicator *bc, size_t len)
{
	const size_t item_len = sizeof(*bc->current_item) + len; 
	struct batch *b = bc->current_batch;
	if((char*)bc->current_item + item_len > (char*)batch_capacity_end(b)) {
		/* New item does not fit in current batch. Send out batch. */
		SAFE_NZ_TRY_EXCEPT(batch_comm_flush(bc),
		                   return NULL);
		/* If new item fits in an empty default preallocated batch,
		   alloc_current_batch will return the default batch. If not,
		   it will create an oversized batch that can fit the item. */
		SAFE_Z_TRY_EXCEPT(b = alloc_current_batch(bc, item_len),
		                  return NULL);
	}
	bc->current_item->length = len;
	bc->current_batch->length += item_len;
	return bc->current_item->contents;
}

int batch_comm_broadcast_reserved(struct batch_communicator *bc)
{
	bc->current_item = next_item(bc->current_item);
	if(bc->current_batch->length >= bc->flush_after
	   || bc->current_item >= batch_capacity_end(bc->current_batch)) {
		SAFE_NZ_TRY_EXCEPT(batch_comm_flush(bc), return 1);
		/* "Freeing" in the flush call above resets the current_batch
		   to an empty preallocated default batch. */
	}
	return 0;
}

void batch_comm_cancel_reserved(struct batch_communicator *bc)
{
	bc->current_batch->length -= sizeof(*bc->current_item)
	                             + bc->current_item->length;
	SAFE_LZ_TRY(bc->current_batch->length);  // assert
	if(bc->current_batch != &bc->preallocated_batch
	   && bc->current_batch->length <= 0) {
		free_current_batch(bc);
	}
	bc->current_item->length = 0;
}
