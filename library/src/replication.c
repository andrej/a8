#include "replication.h"

bool cross_check_args(struct environment *env,
                      struct normalized_args *normalized_args) 
{
	bool ret = false;
	char *serialized_args_buf = NULL;
	size_t serialized_args_buf_len = 0;
	serialized_args_buf = serialize_args(&serialized_args_buf_len,
	                                     normalized_args);
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
	if(-1 == ret) {
		return false;
	}
	return ret;
}

char *serialize_args(size_t *len, struct normalized_args *normalized_args)
{
	size_t n = 0;
	size_t written = 0;
	int n_args = 0;
	char *out = NULL;
	/* If there is no normalize_args() handler, arg_types is initialized to
	   all zeroes. Since IGNORE argument type maps to zero, this simply
	   ignores all arguments and serializes only the system call number. */
	for(int i = 0; i < N_SYSCALL_ARGS; i++) {
		if(IGNORE == normalized_args->arg_types[i].kind) {
			continue;
		}
		n += get_serialized_size(
			(const char *)&normalized_args->args[i], 
		        &normalized_args->arg_types[i]);
		n_args++;
	}
	n += sizeof(uint64_t); // For syscall no
	out = calloc(n, 1);
	if(NULL == out) {
		return NULL;
	}
	memcpy(out, &normalized_args->canonical_no, sizeof(uint64_t));
	written += sizeof(uint64_t);
	for(int i = 0; i < n_args; i++) {
		if(IGNORE == normalized_args->arg_types[i].kind) {
			continue;
		}
		written += serialize_into(
				(const char *)&normalized_args->args[i],
			        &normalized_args->arg_types[i],
			        out + written);
	}
	*len = written;
	return out;
}

void log_args(char *log_buf, size_t max_len, 
              struct normalized_args *normalized_args)
{
	size_t written = 0;
	for(int i = 0; i < N_SYSCALL_ARGS; i++) {
		if(IGNORE == normalized_args->arg_types[i].kind) {
			continue;
		}
		written += snprintf(log_buf + written,
		                    max_len - written,
				    "  Argument %d:\n    ", i);
		written += log_str_of((const char *)&normalized_args->args[i],
		                       &normalized_args->arg_types[i],
		                       log_buf + written, 
		                       max_len - written);
		written += snprintf(log_buf + written,
		                    max_len - written, "\n");
	}
}


int normalize_args(struct environment *env,
	           const struct syscall_handler *handler,
                   struct normalized_args *normalized_args,
		   long args[N_SYSCALL_ARGS])
{
	normalized_args->canonical_no = handler->canonical_no;
	memcpy(normalized_args->args, args, sizeof(normalized_args->args));
	if(NULL != handler->normalize_args) {
		handler->normalize_args(env, normalized_args);
		// TODO check error return
	}
	return 0;
}

int replicate_results(struct environment *env,
	              struct normalized_args *normalized_args,
                      long args[N_SYSCALL_ARGS],
		      long *ret)
{
	size_t replication_buf_len = 0;
	char *replication_buf = NULL;

	if(env->is_leader) {
		replication_buf = get_replication_buffer(normalized_args,
							args, ret,
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
					replication_buf,
					replication_buf_len,
					normalized_args,
					args,
					ret),
			      goto abort1);
	}

	free_and_null(replication_buf);

	return 0;

abort1:
	free_and_null(replication_buf);
	return 1;
}

char *get_replication_buffer(struct normalized_args *normalized_args,
                             long args[N_SYSCALL_ARGS],
                             long *ret,
			     size_t *replication_buf_len)
{
	size_t n = 0;
	ssize_t s = 0;
	size_t written = 0;
	char *replication_buf = NULL;

	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & normalized_args->arg_flags[i])) {
			continue;
		}
		n += get_serialized_size(&args[i], 
		                         &normalized_args->arg_types[i]);
	}
	if(normalized_args->ret_flags & ARG_FLAG_REPLICATE) {
		n += get_serialized_size(ret, &normalized_args->ret_type);
	}
	if(0 == n) {
		return NULL;
	}

	replication_buf = malloc(n);
	if(NULL == replication_buf) {
		return NULL;
	}
	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & normalized_args->arg_flags[i])) {
			continue;
		}
		LZ_TRY_EXCEPT(s = serialize_into(&args[i], 
		                          &normalized_args->arg_types[i],
				          replication_buf + written),
			      return NULL);
		written += s;
	}
	if(normalized_args->ret_flags & ARG_FLAG_REPLICATE) {
		LZ_TRY_EXCEPT(s = serialize_into(ret,
				          &normalized_args->ret_type,
				          replication_buf + written),
			      return NULL);
		written += s;
	}

	*replication_buf_len = written;
	return replication_buf;
}

int write_back_replication_buffer(char *replication_buf,
                                  size_t replication_buf_len,
                                  struct normalized_args *normalized_args,
                                  long args[N_SYSCALL_ARGS],
                                  long *ret)
{
	size_t s = 0;
	size_t consumed = 0;

	for(size_t i = 0; i < N_SYSCALL_ARGS; i++) {
		if(!(ARG_FLAG_REPLICATE & normalized_args->arg_flags[i])) {
			continue;
		}
		LZ_TRY(s = deserialize_overwrite(
				replication_buf + consumed,
		                &normalized_args->arg_types[i],
				&args[i]));
		consumed += s;
	}
	if(normalized_args->ret_flags & ARG_FLAG_REPLICATE) {
		LZ_TRY(s = deserialize_overwrite(
				replication_buf + consumed,
		                &normalized_args->ret_type,
				ret));
		consumed += s;
	}

	if(consumed != replication_buf_len) {
		return 1;
	}

	return 0;
}
