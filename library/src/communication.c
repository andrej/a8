#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "util.h"
#include "communication.h"


/* ************************************************************************** *
 * Internals                                                                  *
 * ************************************************************************** */

#define WELCOME_MESSAGE_SIZE (sizeof(struct message_header) + sizeof(uint64_t))

static inline
int sanity_checks(const struct communicator * const comm)
{
    if(NULL == comm || 0 > comm->self.id || 0 > comm->n_peers
       || MAX_N_PEERS < comm->n_peers) {
        WARN("Communicator failed sanity check.");
        return 1;
    }
    return 0;
}

static int open_tcp_socket()
{
    int fd, ov;

    LZ_TRY_EXCEPT(fd = s.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0),
        goto abort1);

    ov = 1;
    NZ_TRY_EXCEPT(s.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ov, 
                       sizeof(ov)),
        goto abort2);
    NZ_TRY_EXCEPT(s.setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ov, 
                       sizeof(ov)),
        goto abort2);
    // Minimal-latency socket: disable Nagle's algorithm
    NZ_TRY_EXCEPT(s.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ov, 
                       sizeof(ov)),
        goto abort2);
    NZ_TRY_EXCEPT(s.setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &ov, 
                             sizeof(ov)),
        goto abort2);

    return fd;
abort2:
    NZ_TRY_EXCEPT(s.close(fd), exit(1));

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
    addr.sin_port = port;
    NZ_TRY_EXCEPT(s.bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
                  goto abort);
    NZ_TRY_EXCEPT(s.listen(fd, MAX_N_PEERS),
                  goto abort);

    return fd;

abort:
    NZ_TRY_EXCEPT(s.close(fd), exit(1));
    return -1;
}

#if USE_LIBVMA != USE_LIBVMA_SERVER || !USE_ASYNC_WRITE

static int read_all(int fd, char *dest, size_t n)
{
    size_t m = 0;
    while(n > 0) {
        LZ_TRY(m = s.read(fd, dest, n));
        n -= m;
        dest += m;
    }
    return 0;
}

static int write_all(int fd, const char *src, size_t n)
{
    size_t m = 0;
    while(n > 0) {
        LZ_TRY(m = s.write(fd, src, n));
        n -= m;
        src += m;
    }
    return 0;
}

#else

// When using the VMA Server, we submit write requests asynchronously. This
// means a write returns immediately (fire and forget) instead of blocking 
// until the sent data is acknowledged. We submit up to VMA_SERVER_SMEM_SLOTS
// before awaiting the oldest write()s result. If the result indicates an error
// occured while writing, we abort.
static size_t async_requests[VMA_SERVER_SMEM_SLOTS] = {-1};
static size_t async_request_lengths[VMA_SERVER_SMEM_SLOTS] = {-1};
static size_t async_req_head = 0;
static size_t async_req_length = 0;
static void await_oldest_submitted_write()
{
    const size_t oldest = async_requests[async_req_head];
    const size_t oldest_len 
        = async_request_lengths[async_req_head];
    const int ret = vmas_req_async_await_write(oldest, -1, NULL, 0);
    // Abort if we were not successful after assuming we were
    assert(ret == oldest_len);
    async_req_head = (async_req_head + 1) % VMA_SERVER_SMEM_SLOTS;
    async_req_length--;
}
static void await_all_submitted_writes()
{
    while(async_req_length > 0) {
        await_oldest_submitted_write();
    }
}
static int read_all(int fd, char *dest, size_t n)
{
    await_all_submitted_writes();
    size_t m = 0;
    while(n > 0) {
        LZ_TRY(m = s.read(fd, dest, n));
        n -= m;
        dest += m;
    }
    return 0;
}
static size_t write_all(int fd, const char *src, size_t n)
{
    // Perform all writes asynchronously and assume they succeed (return 0).
    // Once a queue of asynchronous writes is full, await the oldest async
    // write's results. If it returns non-zero (error), abort -- we already
    // assumed earlier it would succeed, now it turns out it didn't and we 
    // cannot recover from this (probably wouldn't recover anyways).
    if(async_req_length >= VMA_SERVER_SMEM_SLOTS) {
        // Queue full, await oldest
        await_oldest_submitted_write();
    }
    const size_t tail = 
        (async_req_head + async_req_length) % VMA_SERVER_SMEM_SLOTS;
    async_requests[tail] = 
        vmas_req_async_submit_write(fd, (char *)src, n);
    async_request_lengths[tail] = n;
    async_req_length++;
    return 0; // Assume success
}
#endif

// Throw away the next n bytes to be read from the given file descriptor.
static inline int flush_fd(int fd, size_t n)
{
    const size_t tmp_buf_size = 128;
    char tmp[tmp_buf_size];
    size_t bytes_read = 0;
    while(n > 0) {
        const size_t to_read = (n > sizeof(tmp) ? sizeof(tmp) : n);
        LZ_TRY(bytes_read = s.read(fd, tmp, to_read));
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
    if(NULL == (peer = comm_get_peer_ref(comm, id))) {
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
    NZ_TRY_EXCEPT(init_vma_redirect(), return -1);
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
    LZ_TRY_EXCEPT(comm->self.fd = 
              start_server(own_addr_in->sin_port),
              return -1);
    if(0 == own_addr_in->sin_port) {
        struct sockaddr_in own_name = {};
        socklen_t own_name_len = sizeof(own_name);
        LZ_TRY_EXCEPT(getsockname(comm->self.fd, 
                                  (struct sockaddr *)&own_name,
                      &own_name_len),
                      return -1);
        Z_TRY_EXCEPT(own_name_len == sizeof(own_name), return -1);
        own_port = own_name.sin_port;
    }
    return ntohs(own_port);
}

int comm_destroy(struct communicator *comm)
{
    int ret = 0;
    NZ_TRY_EXCEPT(comm_disconnect_all(comm), ret = 1);
    NZ_TRY(s.close(comm->self.fd));
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
        WARNF("Too many peers already connected (%lu).\n", 
              comm->n_peers);
        return 2;
    }
    if(comm->self.id == peer_id || 0 > peer_id) {
        WARNF("Invalid peer ID %d.\n", peer_id);
        return 1;
    }

    // Check if we have a pending connection with the target ID.
    if(NULL != (peer = comm_get_peer_ref(comm, peer_id))) {
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
            LZ_TRY(fd = s.accept(comm->self.fd, 
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
        peer_addr.sin_port = ((struct sockaddr_in *)sa)->sin_port;
        LZ_TRY(fd = open_tcp_socket());
        LZ_TRY_EXCEPT(s.connect(fd, (struct sockaddr *)&peer_addr, 
                      sizeof(peer_addr)), goto abort);
        NZ_TRY_EXCEPT(write_all(fd, (char *)&welcome_id, 
                               sizeof(welcome_id)), goto abort);
        NZ_TRY_EXCEPT(add_peer(comm, PEER_CONNECTED, peer_id, fd, 
                               (struct sockaddr *)&peer_addr), 
                  goto abort);
    }

    return 0;
abort:
    NZ_TRY_EXCEPT(s.close(fd), exit(1));
    return 1;
}

int comm_disconnect(struct communicator *comm, int peer_id)
{
    const struct peer *peer;
    NZ_TRY(sanity_checks(comm));
    if(0 >= comm->n_peers || 0 > peer_id) {
        return 1;
    }
    if(NULL == (peer = comm_get_peer(comm, peer_id))) {
        WARNF("No such peer %d.\n", peer_id);
        return 1;
    }
    NZ_TRY(s.close(peer->fd));
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

int comm_send(const struct communicator * const comm, int peer_id, size_t n, 
              const char *buf)
{
    const struct peer *peer;
    const struct message_header msg_header = {
        .length = htonl(n)
    };

    NZ_TRY(sanity_checks(comm));
    Z_TRY(peer = comm_get_peer(comm, peer_id));
    Z_TRY(peer->status == PEER_CONNECTED);
    NZ_TRY(write_all(peer->fd, (char *)&msg_header, 
                     sizeof(struct message_header)));
    NZ_TRY(write_all(peer->fd, (char *)buf, n));
    return 0;
}

int comm_receive_header(const struct communicator * const comm, 
                        const struct peer *peer,
                        struct message_header *msg)
{
    // Get peer info
    Z_TRY(peer->status == PEER_CONNECTED);

    // Read message header only
    NZ_TRY(read_all(peer->fd, (char *)msg, sizeof(msg)));
    msg->length = ntohl(msg->length);

    return 0;
}

int comm_receive_body(const struct communicator * const comm,
                      const struct peer *peer,
                      struct message_header *msg,
                      size_t *n, char *buf)
{
    size_t read_n = 0;
    const size_t msg_length = msg->length;

    read_n = (msg_length > *n ? *n : msg_length);
    read_all(peer->fd, buf, read_n);
    *n = msg_length;
    if(read_n < msg_length) {
        // Throw away the remainder of the message because the buffer
        // was too small.
        NZ_TRY(flush_fd(peer->fd, msg_length - read_n));
    }

    return 0;
}

int comm_receive_partial(const struct communicator * const comm, int peer_id, 
                         size_t *n, char *buf)
{
    const struct peer *peer;
    struct message_header msg = {};
    size_t read_n = 0;

    // Get peer info
    NZ_TRY(sanity_checks(comm));
    Z_TRY(peer = comm_get_peer(comm, peer_id));
    Z_TRY(peer->status == PEER_CONNECTED);

    // Get header
    NZ_TRY(comm_receive_header(comm, peer, &msg));

    // Check message size
    NZ_TRY(comm_receive_body(comm, peer, &msg, n, buf));

    return 0;
}

int comm_receive(const struct communicator * const comm, int peer_id, size_t *n,
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

int comm_receive_dynamic(const struct communicator * const comm, int peer_id, 
                         size_t *n, char **buf) {
    const struct peer *peer;
    struct message_header msg = {};
    size_t read_n = 0;
    char *recv_buf = NULL;

    // Get peer info
    NZ_TRY(sanity_checks(comm));
    Z_TRY(peer = comm_get_peer(comm, peer_id));
    Z_TRY(peer->status == PEER_CONNECTED);

    NZ_TRY(comm_receive_header(comm, peer, &msg));

    recv_buf = malloc(msg.length);
    if(NULL == recv_buf) {
        return 1;
    }
    *n = msg.length;
    comm_receive_body(comm, peer, &msg, n, recv_buf);
    *buf = recv_buf;
    return 0;
}

int comm_broadcast(const struct communicator * const comm, size_t n, 
                   const char *buf)
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

int comm_all_agree(const struct communicator * const comm, int leader_id, 
                   size_t n, const char *buf)
{
    int tmp = 0;
    long ret = 1;
    char recv_buf[n];
    size_t n_received = n;

    NZ_TRY_EXCEPT(sanity_checks(comm),
                  return -1);

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
