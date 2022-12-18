#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "util.h"
#include "communication.h"


/* ************************************************************************** *
 * Internals                                                                  *
 * ************************************************************************** */

#define WELCOME_MESSAGE_SIZE (sizeof(struct message) + sizeof(uint64_t))

static inline
int sanity_checks(struct communicator *comm)
{
	if(NULL == comm || 0 > comm->self.id || 0 > comm->n_peers
	   || MAX_N_PEERS < comm->n_peers) {
		WARN("Communicator failed sanity check.");
		return 1;
	}
	return 0;
}

static inline
struct peer *get_peer(struct communicator *comm, int peer_id)
{
	for(size_t i = 0; i < comm->n_peers; i++) {
		if(peer_id == comm->peers[i].id) {
			return &comm->peers[i];
		}
	}
	return NULL;
}

static int open_tcp_socket()
{
	int fd, ov;

	LZ_TRY_EXCEPT(fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0),
		goto abort1);

	ov = 1;
	NZ_TRY_EXCEPT(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov)),
		goto abort2);
	NZ_TRY_EXCEPT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ov, sizeof(ov)),
		goto abort2);
	// Minimal-latency socket: disable Nagle's algorithm
	NZ_TRY_EXCEPT(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ov, sizeof(ov)),
		goto abort2);
	NZ_TRY_EXCEPT(setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &ov, 
	                         sizeof(ov)),
		goto abort2);

	return fd;
abort2:
	NZ_TRY_EXCEPT(close(fd), exit(1));

abort1:
	return -1;
}

static int start_server(in_port_t port)
{
	int fd, ov;
	struct sockaddr_in addr = {};

	LZ_TRY_EXCEPT(fd = open_tcp_socket(), return -1);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	NZ_TRY_EXCEPT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
	              goto abort);
	NZ_TRY_EXCEPT(listen(fd, MAX_N_PEERS),
	              goto abort);

	return fd;

abort:
	NZ_TRY_EXCEPT(close(fd), exit(1));
	return -1;
}

static int read_all(int fd, char *dest, size_t n)
{
	size_t m = 0;
	while(n > 0) {
		LZ_TRY(m = read(fd, dest, n));
		n -= m;
		dest += m;
	}
	return 0;
}

static int write_all(int fd, const char *src, size_t n)
{
	size_t m = 0;
	while(n > 0) {
		LZ_TRY(m = write(fd, src, n));
		n -= m;
		src += m;
	}
	return 0;
}

// Throw away the next n bytes to be read from the given file descriptor.
static inline int flush_fd(int fd, size_t n)
{
	const size_t tmp_buf_size = 128;
	char tmp[tmp_buf_size];
	size_t bytes_read = 0;
	size_t to_read = sizeof(tmp);
	while(n > 0) {
		to_read = (n > sizeof(tmp) ? sizeof(tmp) : n);
		LZ_TRY(bytes_read = read(fd, tmp, to_read));
		n -= bytes_read;
	}
	return 0;
}

static int add_peer(struct communicator *comm, enum peer_status status,
                    int id, int fd, struct sockaddr *sa)
{
	size_t i = 0;
	NZ_TRY(sanity_checks(comm));
	if(comm->n_peers >= MAX_N_PEERS) {
		WARNF("Cannot append peer %d; maximum reached.\n", id);
		return 1;
	}
	i = comm->n_peers;
	comm->peers[i].status = status;
	comm->peers[i].id = id;
	comm->peers[i].fd = fd;
	memcpy(&comm->peers[i].addr, sa, sizeof(struct sockaddr));
	comm->n_peers++;
	return 0;
}

static int delete_peer(struct communicator *comm, int id)
{
	struct peer *peer = NULL;
	struct peer *peer_end = comm->peers + MAX_N_PEERS;
	if(NULL == (peer = get_peer(comm, id))) {
		return 1;
	}
	// Everything after the deleted peer moves up
	if(peer < peer_end - 1) {
		memmove(peer, peer + 1, (char *)peer_end - (char *)peer);
	}
	comm->n_peers--;
	memset(comm->peers + comm->n_peers, 0, 
	       (MAX_N_PEERS-comm->n_peers) * sizeof(struct peer));
	return 0;
}


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int comm_init(struct communicator *comm, int own_id, struct sockaddr *own_addr)
{
	struct sockaddr_in *own_addr_in = (struct sockaddr_in *)own_addr;
	in_port_t own_port = own_addr_in->sin_port;
	if(0 > own_id) {
		WARN("own_id < 0");
		return 1;
	}
	memset(comm, 0, sizeof(struct communicator));
	comm->self.id = own_id;
	comm->self.fd = -1;
	struct sockaddr_in *sa = (struct sockaddr_in *)&comm->self.addr;
	sa->sin_family = AF_INET;
	sa->sin_port = own_port;
	LZ_TRY(comm->self.fd = 
		start_server(own_addr_in->sin_port));
	return 0;
}

int comm_destroy(struct communicator *comm)
{
	int ret = 0;
	NZ_TRY_EXCEPT(comm_disconnect_all(comm), ret = 1);
	NZ_TRY(close(comm->self.fd));
	comm->self.fd = -1;
	return ret;
}

int comm_connect(struct communicator *comm, int peer_id, struct sockaddr *sa)
{
	int fd;
	uint64_t welcome_id;
	struct sockaddr_in peer_addr = {};
	struct peer *peer = NULL;

	// Check if input arguments make sense.
	NZ_TRY(sanity_checks(comm));
	if(MAX_N_PEERS <= comm->n_peers) {
		return 2;
	}
	if(comm->self.id == peer_id || 0 > peer_id) {
		return 1;
	}

	// Check if we have a pending connection with the target ID.
	if(NULL != (peer = get_peer(comm, peer_id))) {
		if(peer->status != PEER_PENDING) {
			WARNF("Peer %d already connected.\n", peer_id);
			return 1;
		}
		peer->status = PEER_CONNECTED;
		return 0;
	}

	// If we have a lower ID, act as the server and await a connection.
	if(peer_id > comm->self.id) {
		do {
			socklen_t addr_len = sizeof(peer_addr);
			LZ_TRY(fd = accept(comm->self.fd, 
			                   (struct sockaddr *)&peer_addr, 
			                   &addr_len));
			NZ_TRY(read_all(fd, (char *)&welcome_id, 
			               sizeof(welcome_id)));
			NZ_TRY(add_peer(comm, PEER_PENDING, 
			                welcome_id, fd,
					(struct sockaddr *)&peer_addr));
		} while(welcome_id != peer_id);
		comm->peers[comm->n_peers-1].status = PEER_CONNECTED;
	}

	// If we have a larger ID, act as the client and connect to the server.
	else {
		welcome_id = comm->self.id;
		peer_addr.sin_family = AF_INET;
		peer_addr.sin_addr = ((struct sockaddr_in *)sa)->sin_addr;
		peer_addr.sin_port = 
			htons(((struct sockaddr_in *)sa)->sin_port);
		LZ_TRY(fd = open_tcp_socket());
		LZ_TRY_EXCEPT(connect(fd, (struct sockaddr *)&peer_addr, 
		              sizeof(peer_addr)), goto abort);
		NZ_TRY_EXCEPT(write_all(fd, (char *)&welcome_id, 
		                       sizeof(welcome_id)), goto abort);
		NZ_TRY_EXCEPT(add_peer(comm, PEER_CONNECTED, peer_id, fd, 
		                       (struct sockaddr *)&peer_addr), 
			      goto abort);
	}

	return 0;
abort:
	NZ_TRY_EXCEPT(close(fd), exit(1));
	return 1;
}

int comm_disconnect(struct communicator *comm, int peer_id)
{
	struct peer *peer;
	NZ_TRY(sanity_checks(comm));
	if(0 >= comm->n_peers || 0 > peer_id) {
		return 1;
	}
	if(NULL == (peer = get_peer(comm, peer_id))) {
		WARNF("No such peer %d.\n", peer_id);
		return 1;
	}
	NZ_TRY(close(peer->fd));
	NZ_TRY(delete_peer(comm, peer_id));
	return 0;
}

int comm_disconnect_all(struct communicator *comm)
{
	int ret = 0;
	NZ_TRY(sanity_checks(comm));
	for(int i = 0; i < comm->n_peers; i++) {
		NZ_TRY_EXCEPT(comm_disconnect(comm, comm->peers[i].id),
		              ret = 1);
	}
	return ret;
}

int comm_send(struct communicator *comm, int peer_id, size_t n, 
              const char *buf)
{
	struct peer *peer;
	size_t len = sizeof(struct message) + n;
	char msg_buf[len];
	struct message *msg = (struct message *)&msg_buf;

	NZ_TRY(sanity_checks(comm));
	Z_TRY(peer = get_peer(comm, peer_id));
	Z_TRY(peer->status == PEER_CONNECTED);
	memset(msg_buf, 0, len);
	msg->length = htonl(n);
	memcpy(msg->data, buf, n);
	NZ_TRY(write_all(peer->fd, (char *)msg, len));
	return 0;
}

int comm_receive_partial(struct communicator *comm, int peer_id, size_t *n,
                         char *buf)
{
	struct peer *peer;
	struct message msg = {};
	size_t read_n = 0;

	// Get peer info
	NZ_TRY(sanity_checks(comm));
	Z_TRY(peer = get_peer(comm, peer_id));
	Z_TRY(peer->status == PEER_CONNECTED);

	// Read message header only
	NZ_TRY(read_all(peer->fd, (char *)&msg, sizeof(msg)));
	msg.length = ntohl(msg.length);

	// Check message size
	read_n = (msg.length > *n ? *n : msg.length);
	read_all(peer->fd, buf, read_n);
	*n = msg.length;
	if(read_n < msg.length) {
		// Throw away the remainder of the message because the buffer
		// was too small.
		NZ_TRY(flush_fd(peer->fd, msg.length - read_n));
	}

	return 0;
}

int comm_receive(struct communicator *comm, int peer_id, size_t *n,
		 char *buf)
{
	size_t n_msg = *n;
	NZ_TRY(comm_receive_partial(comm, peer_id, &n_msg, buf));
	if(n_msg > *n) {
		WARNF("Message about to be received too long for "
			"buffer. Length received %lu, buffer size %lu.\n",
			n_msg, *n);
		return 1;
	}
	*n = n_msg;
	return 0;
}

int comm_receive_dynamic(struct communicator *comm, int peer_id, size_t *n,
                         char **buf) {
	struct peer *peer;
	struct message msg = {};
	size_t read_n = 0;
	char *recv_buf = NULL;

	// Get peer info
	NZ_TRY(sanity_checks(comm));
	Z_TRY(peer = get_peer(comm, peer_id));
	Z_TRY(peer->status == PEER_CONNECTED);

	// Read message header only
	NZ_TRY(read_all(peer->fd, (char *)&msg, sizeof(msg)));
	msg.length = ntohl(msg.length);

	// Check message size
	recv_buf = malloc(msg.length);
	if(NULL == recv_buf) {
		return 1;
	}
	read_all(peer->fd, recv_buf, msg.length);
	*n = msg.length;
	*buf = recv_buf;
	return 0;
}

int comm_broadcast(struct communicator *comm, size_t n, const char *buf)
{
	int ret = 0;
	sanity_checks(comm);
	for(int i = 0; i < comm->n_peers; i++)
	{
		NZ_TRY_EXCEPT(comm_send(comm, comm->peers[i].id, n, buf),
		              ret = 1);
	}
	return ret;
}

int comm_all_agree(struct communicator *comm, int leader_id, size_t n, 
                   const char *buf)
{
	int tmp = 0;
	long ret = 1;
	char recv_buf[n];
	size_t n_received = n;
	sanity_checks(comm);

	// Leader
	if(comm->self.id == leader_id) {
		// Receive all buffers and compare.
		for(int i = 0; i < comm->n_peers; i++) {
			NZ_TRY_EXCEPT(comm_receive_partial(comm, 
			                                   comm->peers[i].id, 
						           &n_received,
							   recv_buf),
				      ret = -1);
			if(ret > 0) {
				if(n_received != n) {
					ret = 0;
				} else if(0 != memcmp(buf, recv_buf, n)) {
					ret = 0;
				}
			}
		}
		// Communicate result back to followers.
		for(int i = 0; i < comm->n_peers; i++) {
			NZ_TRY_EXCEPT(comm_send_p(comm, comm->peers[i].id,
			                             ret),
				      ret = -2);
		}
	}

	// Followers
	else {
		NZ_TRY_EXCEPT(comm_send(comm, leader_id, n, buf),
		              ret = -1);
		tmp = comm_receive_p(comm, leader_id, &ret);
		NZ_TRY_EXCEPT(tmp, ret = -2);
	}

	return (int)ret;
}
