#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <stdint.h>
#include <sys/socket.h>
#include "vma_redirect.h"
#include "util.h"

#ifndef MAX_N_PEERS
#define MAX_N_PEERS 8
#endif

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

#if !NO_HEADERS
struct communicator;
struct message_header;
typedef uint8_t comm_header_t;
typedef int (*comm_check_header_func_t)(const struct communicator *comm,
								        const struct peer *peer, 
								        const struct message_header *msg,
								        comm_header_t expected);
#endif

struct communicator {
	struct peer self;
	size_t n_peers;
	struct peer peers[MAX_N_PEERS];
#if !NO_HEADERS
	comm_check_header_func_t check_header_func;
	comm_header_t expected_next_header;
	comm_header_t outgoing_next_header;
#endif
};

struct __attribute__((packed)) message_header {
	uint32_t length; // length of body (does not include this header struct)
#if !NO_HEADERS
	comm_header_t header; // uniquely identify message type
#endif
};


/**
 * comm_init - Initialize communicator, including server startup. Must be called
 * before any other uses of the communicator.
 * 
 * If 0 is passed for the sin_port field of own_addr, a random port is picked.
 * This port is returned from the function. On error, a negative value is
 * returned.
 * 
 * The port is expected to be in network byte order.
 */
int comm_init(struct communicator *comm, int own_id, struct sockaddr *own_addr);
int comm_destroy(struct communicator *comm);

static inline
const struct peer *
comm_get_peer(const struct communicator * const comm, int peer_id)
{
	for(size_t i = 0; i < comm->n_peers; i++) {
		if(peer_id == comm->peers[i].id) {
			return &comm->peers[i];
		}
	}
	return NULL;
}

/* Return modifiable peer pointer. */
#define comm_get_peer_ref(...) ((struct peer *)comm_get_peer(__VA_ARGS__))

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

int comm_send(const struct communicator * const comm, int peer_id, size_t n, 
              const char *buf);
#define comm_send_p(comm, peer_id, val) comm_send((comm), (peer_id), \
                                                  sizeof(val), (char *)&(val))

int comm_receive_header(const struct communicator * const comm, 
                        const struct peer *peer,
                        struct message_header *msg);

int comm_receive_body(const struct communicator * const comm,
                      const struct peer *peer, const struct message_header *msg,
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
int comm_receive_partial(const struct communicator * const comm, int peer_id, 
                         size_t *n, char *buf);

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
int comm_receive(const struct communicator * const comm, int peer_id, size_t *n, 
                 char *buf);
#define comm_receive_p(comm, peer_id, val) ({ \
	int retval = 0; \
	size_t n = sizeof(*(val)); \
	retval = comm_receive((comm), (peer_id), &n, (char *)(val)); \
	if(n != sizeof(*(val))) { \
		WARNF("Cannot receive primitive, unexpected size %lu instead " \
		      "of %lu\n", n, sizeof(*(val))); \
		retval = 1; \
	} \
	retval; \
})

/**
 * comm_receive_dynamic - Receive arbitrary-length data into an appropriately
 * sized dynamically allocated buffer.
 */
int comm_receive_dynamic(const struct communicator * const comm, int peer_id, 
                         size_t *n, char **buf);

/**
 * comm_broadcast - Call comm_send for the given buffer for each connected peer.
 */
int comm_broadcast(const struct communicator * const comm, size_t n, 
                   const char *buf);
#define comm_broadcast_p(comm, val) comm_broadcast((comm), sizeof(val), \
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
int comm_all_agree(const struct communicator * const comm, int leader_id, 
                   size_t n, const char *buf);
#define comm_all_agree_p(comm, leader_id, val) \
		comm_all_agree((comm), (leader_id), sizeof(val), (char *)&(val))

#if !NO_HEADERS
static inline void 
comm_set_check_header_func(struct communicator *comm,
                           comm_check_header_func_t handler)
{
    comm->check_header_func = handler;
}

/**
 * comm_set_outbound_header - All following outbound messages will use this 
 * one-byte identifier as their message type.
 */
static inline void comm_set_outbound_header(struct communicator *comm,
                                            comm_header_t header)
{
	comm->outgoing_next_header = header;
}

/**
 * comm_expect_incoming_header - All the following incoming messages must have
 * this identifier as their header. If any incoming communication does not have
 * this header, the divergence handler of the communicator is called.
 */
static inline void comm_expect_incoming_header(struct communicator *comm,
                                               comm_header_t header)
{
	comm->expected_next_header = header;
}
#endif


#endif