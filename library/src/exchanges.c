#include "exchanges.h"
#include "batched_communication.h"


/* ************************************************************************** *
 * Internal Forward Declarations / Globals                                    *
 * ************************************************************************** */

//__attribute__((section("protected_state")))
struct batch_communicator preallocated_batch_comm;

__attribute__((aligned(4096)))
char preallocated_batch_comm_memory[PREALLOCATED_REPLICATION_SZ];

/* This buffer does not need to be "protected", since its value is overwritten
   on every system call. */
char cross_check_buffer[CROSS_CHECK_BUFFER_SZ];

static int send_header_without_payload(struct monitor *monitor,
                                       msg_type_t header);
static int expect_header_without_payload(struct monitor *monitor,
                                         msg_type_t header);

static size_t cross_check_get_buffer_size(struct syscall_info *const canonical);
static char * cross_check_alloc_buffer(size_t n);
static int cross_check_serialize_args(char *out, 
                                      struct syscall_info *canonical);

int replication_flush(struct monitor *monitor);
static size_t get_replication_buffer_len(struct syscall_info *canonical);

static int generate_replication_buffer(struct syscall_info *canonical,
                                       char *into, size_t len);

static int write_back_replication_buffer(struct syscall_info *canonical,
                         char *replication_buf,
                         size_t replication_buf_len);

static char *receive_replication_buffer(struct monitor *monitor, 
                                        size_t *len);

#define STR_DEF(X) const char __ ## X ## _strrep[] = #X;
MSG_TYPES(STR_DEF)

#define STR_DEF_LIST(X) __ ## X ## _strrep,
const char *msg_type_strrep[] = {
    MSG_TYPES(STR_DEF_LIST)
};

/* ************************************************************************** *
 * Synchronization                                                            *
 * ************************************************************************** */

int synchronize(struct monitor *monitor, msg_type_t reason)
{
    replication_flush(monitor);
#if !NO_HEADERS
    send_header_without_payload(monitor, reason);   // (6.1)
    expect_header_without_payload(monitor, reason); // (6.2)
#endif
    return 0;
}

static const char unknown_msg_type_strrep[] = "unknown";
const char *msg_type_str(msg_type_t msg)
{
    if(0 > msg || msg > n_msg_types) {
        return unknown_msg_type_strrep;
    }
    return msg_type_strrep[msg];
}

#if !NO_HEADERS
static int send_header_without_payload(struct monitor *monitor,
                                       msg_type_t header)
{
	// assume little endian and fewer than 255 distinct message types
	comm_set_outbound_header(&monitor->comm, header);
    if(monitor->is_leader) {
		SAFE_NZ_TRY(comm_broadcast(&monitor->comm, 0, NULL));
    } else {
		SAFE_NZ_TRY(comm_send(&monitor->comm, monitor->leader_id, 0, NULL));
    }
    return 0;
}

static int expect_header_without_payload(struct monitor *monitor,
                                         msg_type_t header)
{
    size_t header_sz = 0;
	comm_expect_incoming_header(&monitor->comm, (comm_header_t)header);
    if(monitor->is_leader) { 
        for(int i = 0; i < monitor->comm.n_peers; i++) {
            const int peer_id = monitor->comm.peers[i].id;
            if(peer_id == monitor->own_id) {
                continue;
            }
			header_sz = 0;
            SAFE_NZ_TRY(comm_receive_partial(&monitor->comm, peer_id, 
                                             &header_sz, NULL));
			// FIXME this currently won't work properly if divergences occur
			// with > 2 nodes, because the communicator will call the divergence
			// routine on the first diverging received message, instead of 
			// receiving messages from all nodes first and then handling the
			// divergence
        }
    } else {
        SAFE_NZ_TRY(comm_receive_partial(&monitor->comm, monitor->leader_id,
                                         &header_sz, NULL));
    }
	return 0;
}
#endif


/* ************************************************************************** *
 * Cross-Checking                                                             *
 * ************************************************************************** */

int cross_check_args(struct monitor *monitor, struct syscall_info *canonical) 
{
    int s;
    int ret = 1;
    const size_t serialized_len = cross_check_get_buffer_size(canonical);

#if CHECK_HASHES_ONLY
    struct cross_check_message {
        unsigned long hash;
    };
    size_t msg_len = sizeof(struct cross_check_message);
    char serialized_buf[serialized_len]; // temporary for hashing
    struct cross_check_message msg;
    struct cross_check_message * const msg_buf = &msg;
#else
    struct cross_check_message {
        size_t len;
        char data[];  // dynamically sized to serialized_len
    };
    size_t msg_len = sizeof(struct cross_check_message) + serialized_len;
    struct cross_check_message * const msg_buf = 
        (struct cross_check_message *)cross_check_alloc_buffer(msg_len);
    char *serialized_buf = msg_buf->data;
    msg_buf->len = serialized_len;
#endif

    // Serialize own message buffer
    SAFE_NZ_TRY(cross_check_serialize_args(serialized_buf, canonical));

#if CHECK_HASHES_ONLY
    msg_buf->hash = sdbm_hash(serialized_len, serialized_buf);
#endif

    // Communication
    if(monitor->is_leader) { // Leader
        // Flush batched replication buffer, if any
        replication_flush(monitor);

        // Tell followers we are expecting to receive cross-check buffers
        // (1.1) exchange_cross_check_leader_waiting
#if !NO_HEADERS
        SAFE_NZ_TRY(send_header_without_payload(
                        monitor, exchange_cross_check_leader_waiting));
#endif

        int s = 0;
        char recv_buf[msg_len];
        struct cross_check_message * const recv_msg = 
            (struct cross_check_message *)recv_buf;
        size_t n_received = msg_len;

        // Receive all buffers and compare.
        for(int i = 0; i < monitor->comm.n_peers; i++) {
#if !NO_HEADERS
            // (2.2) exchange_cross_check_follower_buffer
			comm_expect_incoming_header(
                &monitor->comm, exchange_cross_check_follower_buffer);
#endif
            SAFE_NZ_TRY(comm_receive_partial(&monitor->comm, 
                                             monitor->comm.peers[i].id, 
                                            &n_received, recv_buf));
            ret = ret && n_received == msg_len;
#if CHECK_HASHES_ONLY
            ret = ret && msg_buf->hash == recv_msg->hash;
#else
            ret = ret && 0 == memcmp(msg_buf->data, recv_msg->data, 
                                     serialized_len);
#endif
        }
        // Communicate result back to followers.
        for(int i = 0; i < monitor->comm.n_peers; i++) {
            s = comm_broadcast_p(&monitor->comm, ret);
            SAFE_NZ_TRY(s);
        }
    } else { // Followers
#if !NO_HEADERS
        // (2.1) exchange_cross_check_follower_buffer 
		comm_set_outbound_header(&monitor->comm,
                                 exchange_cross_check_follower_buffer);
#endif
        SAFE_NZ_TRY(comm_send(&monitor->comm, monitor->leader_id, 
                              msg_len, (char *)msg_buf));
#if !NO_HEADERS
        // (1.2) exchange_cross_check_leader_waiting
		expect_header_without_payload(monitor,
		                              exchange_cross_check_leader_waiting);
#endif
        s = comm_receive_p(&monitor->comm, monitor->leader_id, &ret);
        SAFE_NZ_TRY(s);
    }
    
#if !CHECK_HASHES_ONLY
    if(cross_check_buffer != (char *)msg_buf) {
        safe_free(msg_buf, msg_len);
    }
#endif
    return ret;
}

static size_t cross_check_get_buffer_size(struct syscall_info * const canonical)
{
    size_t n = 0;
    /* If there is no normalize_args() handler, arg_types is initialized to
       all zeroes. Since IGNORE argument type maps to zero, this simply
       ignores all arguments and serializes only the system call number. */
    for(int i = 0; i < N_SYSCALL_ARGS; i++) {
        if(IGNORE == canonical->arg_types[i].kind ||
           ARG_FLAG_WRITE_ONLY & canonical->arg_flags[i]) {
            continue;
        }
        n += get_serialized_size((const char *)&canonical->args[i], 
                                 &canonical->arg_types[i]);
    }
    n += sizeof(uint64_t); // For syscall no
    return n;
}

static char * cross_check_alloc_buffer(size_t n)
{
    if(n > sizeof(cross_check_buffer)) {
        char * const out = safe_malloc(n);
        if(NULL == out) {
            return NULL;
        }
        return out;
    } else {
        return cross_check_buffer;
    }
}

static int cross_check_serialize_args(char *out, struct syscall_info *canonical)
{
    size_t written = 0;
    ssize_t s = 0;
    *(uint64_t *)out = canonical->no;
    written += sizeof(uint64_t);
    for(int i = 0; i < N_SYSCALL_ARGS; i++) {
        if(IGNORE == canonical->arg_types[i].kind ||
           ARG_FLAG_WRITE_ONLY & canonical->arg_flags[i]) {
            continue;
        }
        s = serialize_into((const char *)&canonical->args[i], 
                           &canonical->arg_types[i], out + written);
        if(s < 0) {
            return 1;
        }
        written += s;
    }
    return 0;
}

void log_args(char *log_buf, size_t max_len, 
              struct syscall_info *actual,
              struct syscall_info *canonical)
{
    #define append(...) { \
        if(written >= max_len) { \
            return; \
        } \
        written += snprintf(log_buf + written, max_len - written, \
                            __VA_ARGS__); \
    }
    size_t written = 0;
    append("Canonical no. %ld (actual no. %ld) args:\n", canonical->no, 
           actual->no);
    for(int i = 0; i < N_SYSCALL_ARGS; i++) {
        if(IGNORE == canonical->arg_types[i].kind) {
            continue;
        }
        append("  Argument %d: (%ld) \n    ", i, actual->args[i]);
        if(canonical->arg_flags[i] & ARG_FLAG_WRITE_ONLY) {
            append("(write only)");
        } else {
            written += log_str_of((const char *)&canonical->args[i],
                    &canonical->arg_types[i],
                    log_buf + written, 
                    max_len - 1 - written);
        }
        append("\n");
    }
    #undef append
}


/* ************************************************************************** *
 * Results Replication                                                        *
 * ************************************************************************** */

int replication_init(struct monitor * const monitor, size_t flush_after)
{
    const struct peer *leader_peer = NULL;
    if(!monitor->is_leader) {
        Z_TRY(leader_peer = comm_get_peer(&monitor->comm, 
                                          monitor->leader_id));
    }
    monitor->batch_comm = &preallocated_batch_comm;

    NZ_TRY(init_batch_comm_at(&preallocated_batch_comm,
                              preallocated_batch_comm_memory,
                              &monitor->comm, leader_peer, 
                              PREALLOCATED_REPLICATION_SZ, 
                              flush_after));
    return 0;
}

void replication_destroy(struct monitor * const monitor)
{
    SAFE_NZ_TRY(replication_flush(monitor)); 
    if(monitor->batch_comm != &preallocated_batch_comm) {
        free_batch_comm(monitor->batch_comm);
    }
}

int replication_flush(struct monitor *monitor)
{
    msg_type_t header;
    if(monitor->is_leader) {
        // Allow followers waiting on batched communication to catch up.
#if !NO_HEADERS
        const bool header_expected = 
            batch_comm_flush_will_communicate(monitor->batch_comm);
        if(header_expected) {
            // (4.1) exchange_replication_leader
            comm_set_outbound_header(
                &monitor->comm, exchange_replication_leader);
        }
#endif
        SAFE_NZ_TRY(batch_comm_flush(monitor->batch_comm));
#if !NO_HEADERS
        if(header_expected) {
            // (3.2) exchange_replication_follower_waiting
            // -> receipt of this message from the follower is also 
            //    alternatively checked in replicate_results
            SAFE_NZ_TRY(expect_header_without_payload(monitor, 
                                      exchange_replication_follower_waiting));
        }
#endif
    }
    return 0;
}

int replicate_results(struct monitor *monitor,
                      struct syscall_info *canonical)
{
    char *msg_buf = NULL;
    size_t msg_len = 0;

    if(monitor->is_leader) {
        int n_exchanges = 0;
        msg_len = get_replication_buffer_len(canonical);
#if VERBOSITY >= 4
        SAFE_LOGF("Appending %lu bytes of replication information to batch.\n",
                  msg_len);
#endif
#if !NO_HEADERS
        if(batch_comm_reserve_will_communicate(monitor->batch_comm, msg_len)) {
            // (4.1) exchange_replication_leader
			comm_set_outbound_header(
				&monitor->comm, exchange_replication_leader);
            n_exchanges++;
        }
#endif
        SAFE_Z_TRY(msg_buf = batch_comm_reserve(monitor->batch_comm, msg_len));
        SAFE_NZ_TRY(generate_replication_buffer(canonical, msg_buf, msg_len));
#if !NO_HEADERS
        if(batch_comm_broadcast_reserved_will_communicate(monitor->batch_comm)){
            // (4.1) exchange_replication_leader
			comm_set_outbound_header(
				&monitor->comm, exchange_replication_leader);
            n_exchanges++;
        }
#endif
        SAFE_NZ_TRY(batch_comm_broadcast_reserved(monitor->batch_comm));
#if !NO_HEADERS
        for(int i = 0; i < n_exchanges; i++) {
            // For each actual network communication we send out, we should
            // receive a matching header from the follower saying that it is
            // expecting replication information. Verify this and throw away.
            // (3.2) exchange_replication_follower_waiting
            // -> receipt of this message from the follower is also 
            //    alternatively checked in replication_flush
            SAFE_NZ_TRY(expect_header_without_payload(monitor, 
                                      exchange_replication_follower_waiting));
        }
#endif
    } else {
#if VERBOSITY >= 4
        SAFE_LOG("Awaiting replication information from leader.\n");
#endif
#if !NO_HEADERS
        if(batch_comm_receive_will_communicate(monitor->batch_comm)) {
            // (3.1) exchange_replication_follower_waiting
            SAFE_NZ_TRY(send_header_without_payload(monitor, 
                                    exchange_replication_follower_waiting));
            // (4.2) exchange_replication_leader
            comm_expect_incoming_header(
				&monitor->comm, exchange_replication_leader);
        }
#endif
        SAFE_Z_TRY(msg_buf = batch_comm_receive(monitor->batch_comm, &msg_len));
        // (4.2) exchange_replication_leader
        SAFE_NZ_TRY(write_back_replication_buffer(canonical, msg_buf, msg_len));
    }

    return 0;
}

static size_t get_replication_buffer_len(struct syscall_info *canonical)
{
    size_t n = sizeof(uint64_t);
    for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
        if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
            continue;
        }
        n += get_serialized_size(&canonical->args[i], 
                                 &canonical->arg_types[i]);
    }
    if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
        n += get_serialized_size(&canonical->ret, &canonical->ret_type);
    }
    return n;
}

static int generate_replication_buffer(struct syscall_info *canonical,
                                       char *into, size_t len)
{
    ssize_t s = 0;
    size_t written = 0;
    SAFE_Z_TRY(into);  // assert

    *(uint64_t *)into = canonical->no;
    written += sizeof(uint64_t);

    for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
        if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
            continue;
        }
        SAFE_LZ_TRY_EXCEPT(
            s = serialize_into(&canonical->args[i], 
                                   &canonical->arg_types[i],
                               into + written),
            return 1);
        written += s;
    }
    if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
        SAFE_LZ_TRY_EXCEPT(
            s = serialize_into(&canonical->ret,
                           &canonical->ret_type,
                           into + written),
            return 1);
        written += s;
    }

    SAFE_Z_TRY(len == written);  // assert
    return 0;
}

static int write_back_replication_buffer(struct syscall_info *canonical,
                         char *replication_buf,
                         size_t replication_buf_len)
{
    size_t s = 0;
    size_t consumed = 0;

    if(replication_buf_len < sizeof(uint64_t)) {
        return 1;
    }
    if(*(uint64_t *)replication_buf != canonical->no) {
        return 2;
    }
    consumed += sizeof(uint64_t);

    for(size_t i = 0; i < N_SYSCALL_ARGS && consumed < replication_buf_len; 
        i++) {
        if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
            continue;
        }
        SAFE_LZ_TRY_EXCEPT(
            s = deserialize_overwrite(replication_buf + consumed,
                                      replication_buf_len - consumed,
                                      &canonical->arg_types[i],
                                      &canonical->args[i]),
            return 1);
        consumed += s;
    }
    if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
        SAFE_LZ_TRY_EXCEPT(
            s = deserialize_overwrite(replication_buf + consumed,
                                      replication_buf_len - consumed,
                                      &canonical->ret_type,
                                      &canonical->ret),
            return 1);
        consumed += s;
    }

    if(consumed != replication_buf_len) {
        return 1;
    }

    return 0;
}
