#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <stdint.h>
#include <sys/socket.h>

#include "util.h"

#define MAX_N_PEERS 8

enum peer_status {
	PEER_PENDING,
	PEER_CONNECTED,
	PEER_DISCONNECTED
};

struct peer {
	enum peer_status status;
	int id;
	int fd;
	struct sockaddr addr;
};

struct communicator {
	struct peer self;
	size_t n_peers;
	struct peer peers[MAX_N_PEERS];
};

struct __attribute__((packed)) message {
	uint64_t length;
	char data[];
};

/**
 * comm_init - Initialize communicator, including server startup. Must be called
 * before any other uses of the communicator.
 */
int comm_init(struct communicator *comm, int own_id, struct sockaddr *own_addr);
int comm_destroy(struct communicator *comm);

static inline
struct peer *comm_get_peer(struct communicator *comm, int peer_id)
{
	for(size_t i = 0; i < comm->n_peers; i++) {
		if(peer_id == comm->peers[i].id) {
			return &comm->peers[i];
		}
	}
	return NULL;
}

/**
 * comm_connect - Establish a bidirectional connection with peer with ID 
 * peer_id at address peer_addr; a corresponding call to this function must be 
 * made from that peer as well. The lower-ID peer will act as a server, awaiting
 * an incoming connection from the higher-ID peer.
 */
int comm_connect(struct communicator *comm, int peer_id, 
                 struct sockaddr *peer_addr);

int comm_disconnect(struct communicator *comm, int peer_id);
int comm_disconnect_all(struct communicator *comm);

int comm_send(struct communicator *comm, int peer_id, size_t n, 
              const char *buf);
#define comm_send_p(comm, peer_id, val) comm_send(comm, peer_id, \
                                                  sizeof(val), (char *)&(val))

int comm_receive_header(struct communicator *comm, 
                        struct peer *peer,
                        struct message *msg);

int comm_receive_body(struct communicator *comm,
                     struct peer *peer,
                     struct message *msg,
                     size_t *n, char *buf);

/**
 * comm_receive_partial - Same as comm_receive except for differing behavior
 * when the message to be received is larger than the buffer. Other than
 * comm_receive, if the message to be received is larger than the buffer, this
 * function
 * (1) Sets *n to be the actual message size, which can be larger than the
 *     original value (buffer size).
 * (2) Returns 0 to indicate a successful partial read, i.e. even if parts of 
 *     the message had to be thrown away due to larger size.
 */
int comm_receive_partial(struct communicator *comm, int peer_id, size_t *n, 
                         char *buf);

/**
 * comm_receive - Receives the next message of up to *n bytes from peer_id into 
 * buf. 
 * 
 * The argument n must point to a size_t which initially holds the value of the
 * size of the buffer buf. After receiving the message, that value will be
 * set to the actual number of bytes received, which may be less than or equal
 * to the size of the buffer initially passed in. It will never be set to a 
 * larger value.
 * 
 * If the the next message to be received is larger than the buffer size passed
 * in *n, the first *n bytes will be read into buf and the rest of the message 
 * will be flushed. A warning will be printed and an error return value of 1
 * returned -- this differs from the behavior of comm_receive_partial.
 */
int comm_receive(struct communicator *comm, int peer_id, size_t *n, 
                 char *buf);
#define comm_receive_p(comm, peer_id, val) ({ \
	int retval = 0; \
	size_t n = sizeof(*(val)); \
	retval = comm_receive((comm), (peer_id), &n, (char *)(val)); \
	if(n != sizeof(*(val))) { \
		WARNF("Cannot receive primitive, unexpected size %lu instead" \
		      "of %lu", n, sizeof(*(val))); \
		retval = 1; \
	} \
	retval; \
})

/**
 * comm_receive_dynamic - Receive arbitrary-length data into an appropriately
 * sized dynamically allocated buffer.
 */
int comm_receive_dynamic(struct communicator *comm, int peer_id, size_t *n,
                         char **buf);

/**
 * comm_broadcast - Call comm_send for the given buffer for each connected peer.
 */
int comm_broadcast(struct communicator *comm, size_t n, const char *buf);
#define comm_broadcast_p(comm, val) comm_broadcast(comm, sizeof(val), \
                                                   (char *)&(val))

/**
 * comm_all_agree - Return 1 if all connected peers issued a comm_all_agree
 * call with identical n and *buf arguments, 0 if the inputs differ, or -1 if
 * an error occured during communications. 
 * 
 * leader_id is the ID of a connected peer or of this communicator itself. On 
 * all peers, calls to this function must use the same leader ID. All peers
 * except for the leader will send their buffer to the leader. The leader 
 * receives all buffers and compares them; if identical, it broadcasts 1 to all
 * nodes, 0 otherwise. 
 */
int comm_all_agree(struct communicator *comm, int leader_id, size_t n, 
                   const char *buf);
#define comm_all_agree_p(comm, leader_id, val) \
		comm_all_agree(comm, leader_id, sizeof(val), (char *)&(val))


#endif