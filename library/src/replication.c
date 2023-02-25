#include "replication.h"
#include "batched_communication.h"


/* ************************************************************************** *
 * Internal Forward Declarations                                              *
 * ************************************************************************** */

#define CROSS_CHECK_BUFFER_SZ 4096
char cross_check_buffer[CROSS_CHECK_BUFFER_SZ];

struct batch_communicator *bc = NULL;

static char *serialize_args(size_t *len, struct syscall_info *canonical);

static size_t get_replication_buffer_len(struct syscall_info *canonical);

static int generate_replication_buffer(struct syscall_info *canonical,
                                       char *into, size_t len);

static int write_back_replication_buffer(struct syscall_info *canonical,
				         char *replication_buf,
				         size_t replication_buf_len);

static char *receive_replication_buffer(struct environment *env, size_t *len);


/* ************************************************************************** *
 * Cross-Checking                                                             *
 * ************************************************************************** */

int cross_check_args(struct environment *env,
                      struct syscall_info *canonical) 
{
	bool ret = false;
	char *serialized_args_buf = NULL;
	size_t serialized_args_buf_len = 0;

	if(env->is_leader) {
		SAFE_NZ_TRY_EXCEPT(batch_comm_flush(bc),
		                   return -1);
	}

	serialized_args_buf = serialize_args(&serialized_args_buf_len,
	                                     canonical);
	if(NULL == serialized_args_buf) {
		return false;
	}
#if CHECK_HASHES_ONLY
	const unsigned long hash = sdbm_hash(serialized_args_buf_len,
					     serialized_args_buf);
	char * const cross_check_buf = (char * const)&hash;
	size_t cross_check_buf_len = sizeof(hash);
#else
	char * const cross_check_buf = (char * const)serialized_args_buf;
	size_t cross_check_buf_len = serialized_args_buf_len;
#endif
	ret = comm_all_agree(env->comm, env->leader_id,
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

int init_replication(struct environment *env, size_t size)
{
	struct peer *leader_peer = NULL;
	if(!env->is_leader) {
		Z_TRY(leader_peer = comm_get_peer(env->comm, env->leader_id));
	}
	Z_TRY(bc = init_batch_comm(env->comm, leader_peer, size));
	return 0;
}

void free_replication()
{
	SAFE_NZ_TRY(batch_comm_flush(bc));	
	free_batch_comm(bc);
}

int replicate_results(struct environment *env,
	              struct syscall_info *canonical,
		      bool force_send)
{
	size_t len = 0;
	size_t recv_len = 0;
	char *buf = NULL;

	len = get_replication_buffer_len(canonical);
	if(0 == len) {
		return 0;  // nothing to replicate
	}

	if(env->is_leader) {
		SAFE_Z_TRY_EXCEPT(
			buf = batch_comm_reserve(bc, len),
			goto abort0);
		SAFE_NZ_TRY_EXCEPT(
			generate_replication_buffer(canonical, buf, len),
			goto abort1);
		SAFE_NZ_TRY_EXCEPT(
			batch_comm_broadcast_reserved(bc, force_send),
			goto abort1);
	} else {
		SAFE_Z_TRY_EXCEPT(
			buf = batch_comm_receive(bc, &recv_len),
			goto abort1);
		SAFE_Z_TRY(recv_len == len);  // assert
		SAFE_NZ_TRY_EXCEPT(
			write_back_replication_buffer(canonical, buf, len),
			goto abort1);
	}

	return 0;

abort1:
	if(env->is_leader) {
		batch_comm_cancel_reserved(bc);
	}
abort0:
	return 1;
}

static size_t get_replication_buffer_len(struct syscall_info *canonical)
{
	size_t n = 0;
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

	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
			continue;
		}
		SAFE_LZ_TRY(
			s = deserialize_overwrite(replication_buf + consumed,
		                                  &canonical->arg_types[i],
				                  &canonical->args[i]));
		consumed += s;
	}
	if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
		SAFE_LZ_TRY(
			s = deserialize_overwrite(replication_buf + consumed,
		                                  &canonical->ret_type,
		                                  &canonical->ret));
		consumed += s;
	}

	if(consumed != replication_buf_len) {
		return 1;
	}

	return 0;
}
