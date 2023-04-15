#include "exchanges.h"
#include "batched_communication.h"


/* ************************************************************************** *
 * Internal Forward Declarations / Globals                                    *
 * ************************************************************************** */

//__attribute__((section("protected_state")))
struct batch_communicator preallocated_batch_comm;

char preallocated_batch_comm_memory[PREALLOCATED_REPLICATION_SZ];

/* This buffer does not need to be "protected", since its value is overwritten
   on every system call. */
char cross_check_buffer[CROSS_CHECK_BUFFER_SZ];

static char *serialize_args(size_t *len, struct syscall_info *canonical);

static size_t get_replication_buffer_len(struct syscall_info *canonical);

static int generate_replication_buffer(struct syscall_info *canonical,
                                       char *into, size_t len);

static int write_back_replication_buffer(struct syscall_info *canonical,
				         char *replication_buf,
				         size_t replication_buf_len);

static char *receive_replication_buffer(const struct monitor * const monitor, 
                                        size_t *len);


/* ************************************************************************** *
 * Synchronization                                                            *
 * ************************************************************************** */

int synchronize(const struct monitor * const monitor, char reason)
{
	if(monitor->is_leader && REPLICATION_EXCHANGE != reason) {
		// Allow followers waiting on batched communication to catch up.
		if(batch_comm_flush_will_communicate(monitor->batch_comm)) {
			SAFE_NZ_TRY_EXCEPT(synchronize(monitor, 
			                               REPLICATION_EXCHANGE),
					   return -1);
		}
		SAFE_NZ_TRY_EXCEPT(batch_comm_flush(monitor->batch_comm),
				   return -1);
	}
	int s = 0;
	SAFE_LZ_TRY_EXCEPT(s = comm_all_agree_p(&monitor->comm, 
	                                        monitor->leader_id,
					        reason),
			   return -1);
	if(0 == s) {
		return monitor->handle_divergence(monitor, reason);
	} else if(1 == s && ERROR_EXCHANGE == reason) {
		return monitor->handle_error(monitor);
	}
	return 0;
}


/* ************************************************************************** *
 * Cross-Checking                                                             *
 * ************************************************************************** */

int cross_check_args(const struct monitor * const monitor,
                      struct syscall_info *canonical) 
{
	bool ret = false;
	char *serialized_args_buf = NULL;
	size_t serialized_args_buf_len = 0;

	SAFE_NZ_TRY(synchronize(monitor, CROSS_CHECK_EXCHANGE));

	serialized_args_buf = serialize_args(&serialized_args_buf_len,
	                                     canonical);
	if(NULL == serialized_args_buf) {
		return false;
	}
#if CHECK_HASHES_ONLY
	unsigned long hash = sdbm_hash(serialized_args_buf_len, 
	                               serialized_args_buf);
	char * cross_check_buf = (char * const)&hash;
	size_t cross_check_buf_len = sizeof(hash);
#else
	char * cross_check_buf = (char * const)serialized_args_buf;
	size_t cross_check_buf_len = serialized_args_buf_len;
#endif
	ret = comm_all_agree(&monitor->comm, monitor->leader_id,
	                     cross_check_buf_len,
	                     cross_check_buf);
	if(cross_check_buffer != serialized_args_buf) {
		safe_free(serialized_args_buf, serialized_args_buf_len);
	}
	if(0 > ret) {
		return -1;
	}
	return ret;
}

char *serialize_args(size_t *len, struct syscall_info *canonical)
{
	size_t n = 0;
	size_t written = 0;
	int n_args = 0;
	char *out = NULL;
	/* If there is no normalize_args() handler, arg_types is initialized to
	   all zeroes. Since IGNORE argument type maps to zero, this simply
	   ignores all arguments and serializes only the system call number. */
	for(int i = 0; i < N_SYSCALL_ARGS; i++) {
		if(IGNORE == canonical->arg_types[i].kind ||
		   ARG_FLAG_WRITE_ONLY & canonical->arg_flags[i]) {
			continue;
		}
		n += get_serialized_size(
			(const char *)&canonical->args[i], 
		        &canonical->arg_types[i]);
		n_args++;
	}
	n += sizeof(uint64_t); // For syscall no
	out = cross_check_buffer;
	if(n > sizeof(cross_check_buffer)) {
		out = safe_malloc(n);
	}
	if(NULL == out) {
		return NULL;
	}
	memcpy(out, &canonical->no, sizeof(uint64_t));
	written += sizeof(uint64_t);
	for(int i = 0; i < n_args; i++) {
		if(IGNORE == canonical->arg_types[i].kind ||
		   ARG_FLAG_WRITE_ONLY & canonical->arg_flags[i]) {
			continue;
		}
		written += serialize_into(
				(const char *)&canonical->args[i],
			        &canonical->arg_types[i],
			        out + written);
	}
	*len = written;
	return out;
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
					max_len - written);
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
	SAFE_NZ_TRY(batch_comm_flush(monitor->batch_comm));	
	if(monitor->batch_comm != &preallocated_batch_comm) {
		free_batch_comm(monitor->batch_comm);
	}
}

int replicate_results(const struct monitor * const monitor,
	              struct syscall_info *canonical)
{
	size_t recv_len = 0;
	char *buf = NULL;


	if(monitor->is_leader) {
		const size_t len = get_replication_buffer_len(canonical);
		if(batch_comm_reserve_will_communicate(monitor->batch_comm,
		                                       len)) {
			SAFE_NZ_TRY(synchronize(monitor, REPLICATION_EXCHANGE));
		}
		SAFE_Z_TRY_EXCEPT(
			buf = batch_comm_reserve(monitor->batch_comm, len),
			goto abort0);
		SAFE_NZ_TRY_EXCEPT(
			generate_replication_buffer(canonical, buf, len),
			goto abort1);
		if(batch_comm_broadcast_reserved_will_communicate(
			monitor->batch_comm)) {
			SAFE_NZ_TRY(synchronize(monitor, REPLICATION_EXCHANGE));
		}
		SAFE_NZ_TRY_EXCEPT(
			batch_comm_broadcast_reserved(monitor->batch_comm),
			goto abort1);
	} else {
		if(batch_comm_receive_will_communicate(monitor->batch_comm)) {
			SAFE_NZ_TRY(synchronize(monitor, REPLICATION_EXCHANGE));
		}
		SAFE_Z_TRY_EXCEPT(
			buf = batch_comm_receive(monitor->batch_comm, 
			                         &recv_len),
			goto abort1);
		SAFE_NZ_TRY_EXCEPT(
			write_back_replication_buffer(canonical, buf, recv_len),
			goto abort1);
	}

	return 0;

abort1:
	if(monitor->is_leader) {
		batch_comm_cancel_reserved(monitor->batch_comm);
	}
abort0:
	SAFE_NZ_TRY_EXCEPT(synchronize(monitor, ERROR_EXCHANGE),
		           return 2);
	return 1;
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
			                          replication_buf_len-consumed,
		                                  &canonical->arg_types[i],
				                  &canonical->args[i]),
			return 1);
		consumed += s;
	}
	if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
		SAFE_LZ_TRY_EXCEPT(
			s = deserialize_overwrite(replication_buf + consumed,
			                          replication_buf_len-consumed,
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
