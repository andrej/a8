#include "replication.h"

int cross_check_args(struct environment *env,
                      struct syscall_info *canonical) 
{
	bool ret = false;
	char *serialized_args_buf = NULL;
	size_t serialized_args_buf_len = 0;
	serialized_args_buf = serialize_args(&serialized_args_buf_len,
	                                     canonical);
	if(NULL == serialized_args_buf) {
		return false;
	}
#if CHECK_HASHES_ONLY
	const unsigned long hash = sdbm_hash(serialized_args_buf_len,
					     serialized_args_buf);
	free_and_null(serialized_args_buf);
	serialized_args_buf = malloc(sizeof(unsigned long));
	memcpy(serialized_args_buf, &hash, sizeof(hash));
	serialized_args_buf_len = sizeof(hash);
#endif
	ret = comm_all_agree(env->comm, env->leader_id,
	                     serialized_args_buf_len,
			     serialized_args_buf);
	free_and_null(serialized_args_buf);
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
	out = calloc(n, 1);
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

int replicate_results(struct environment *env,
	              struct syscall_info *canonical)
{
	size_t replication_buf_len = 0;
	char *replication_buf = NULL;

	if(env->is_leader) {
		replication_buf = get_replication_buffer(
			canonical,
			&replication_buf_len);
		if(NULL == replication_buf) {
			return 1;
		}
		NZ_TRY_EXCEPT(comm_broadcast(env->comm, replication_buf_len, 
		                             replication_buf),
			      goto abort1);
	} else {
		NZ_TRY(comm_receive_dynamic(env->comm, env->leader_id, 
		                            &replication_buf_len, 
		                            &replication_buf));
		NZ_TRY_EXCEPT(write_back_replication_buffer(
					canonical,
					replication_buf,
					replication_buf_len),
			      goto abort1);
	}

	free_and_null(replication_buf);

	return 0;

abort1:
	free_and_null(replication_buf);
	return 1;
}

char *get_replication_buffer(struct syscall_info *canonical,
			     size_t *replication_buf_len)
{
	size_t n = 0;
	ssize_t s = 0;
	size_t written = 0;
	char *replication_buf = NULL;

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
	if(0 == n) {
		return NULL;
	}

	replication_buf = malloc(n);
	if(NULL == replication_buf) {
		return NULL;
	}
	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
			continue;
		}
		LZ_TRY_EXCEPT(s = serialize_into(&canonical->args[i], 
		                          &canonical->arg_types[i],
				          replication_buf + written),
			      return NULL);
		written += s;
	}
	if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
		LZ_TRY_EXCEPT(s = serialize_into(&canonical->ret,
				          &canonical->ret_type,
				          replication_buf + written),
			      return NULL);
		written += s;
	}

	*replication_buf_len = written;
	return replication_buf;
}

int write_back_replication_buffer(struct syscall_info *canonical,
				  char *replication_buf,
				  size_t replication_buf_len)
{
	size_t s = 0;
	size_t consumed = 0;

	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & canonical->arg_flags[i])) {
			continue;
		}
		LZ_TRY(s = deserialize_overwrite(
				replication_buf + consumed,
		                &canonical->arg_types[i],
				&canonical->args[i]));
		consumed += s;
	}
	if(canonical->ret_flags & ARG_FLAG_REPLICATE) {
		LZ_TRY(s = deserialize_overwrite(
				replication_buf + consumed,
		                &canonical->ret_type,
				&canonical->ret));
		consumed += s;
	}

	if(consumed != replication_buf_len) {
		return 1;
	}

	return 0;
}
