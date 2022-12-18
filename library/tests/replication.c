#include <string.h>

#include "test_suite/test.h"
#include "replication.h"

TEST(replicate_write_back)
{
	struct simple {
		short a;
		char *b;
	};

	char buf1[] = "Hello!";
	char buf2[] = "Howdy."; 
	char buf3[] = "Hey";
	char buf4[] = "Hi ";
	struct simple s1 = {456, buf3};
	struct simple s2 = {789, buf4};

	long ret_leader = 42;
	long ret_follower = 12;

	long args_leader[N_SYSCALL_ARGS] = {
		128,
		129,
		(long)buf1,
		(long)&s1
	};
	long args_follower[N_SYSCALL_ARGS] = {
		99,   // replication should ignore this one
		100,  // replication should overwrite this one with 129
		(long)buf2, // replication should overwrite buffer buf1 into 
		            // buf2, but leave pointer argument unchanged
		(long)&s2 // replication should overwrite referenced pointer 
		          // inside pointed-to struct and update struct fields
	};

	struct normalized_args normal;

	// Arg 1 type
	struct type arg1_type = IGNORE_TYPE();
	normal.arg_types[0] = arg1_type;
	normal.arg_flags[0] = ARG_FLAG_NONE;

	// Arg 2 type
	struct type arg2_type = IMMEDIATE_TYPE(sizeof(long));
	normal.arg_types[1] = arg2_type;
	normal.arg_flags[1] = ARG_FLAG_REPLICATE;

	// Arg 3 type
	struct type arg3_buf_type = BUFFER_TYPE(sizeof(buf1));
	struct type arg3_type = POINTER_TYPE(&arg3_buf_type);
	normal.arg_types[2] = arg3_type;
	normal.arg_flags[2] = ARG_FLAG_REPLICATE;

	// Arg 4 type
	struct type arg4_buf_ptr_buf_type = BUFFER_TYPE(sizeof(sizeof(buf3)));
	struct type arg4_buf_ptr_type = POINTER_TYPE(&arg4_buf_ptr_buf_type);
	struct buffer_reference arg4_buf_refs[] = {{(void *)&s1.b-(void *)&s1,
	                                           &arg4_buf_ptr_type}};
	struct type arg4_buf_type = BUFFER_TYPE(sizeof(struct simple),
	                                        1, arg4_buf_refs);
	struct type arg4_type = POINTER_TYPE(&arg4_buf_type);
	normal.arg_types[3] = arg4_type;
	normal.arg_flags[3] = ARG_FLAG_REPLICATE;

	// Return type
	struct type ret_type = IMMEDIATE_TYPE(sizeof(long));
	normal.ret_type = ret_type;
	normal.ret_flags = ARG_FLAG_REPLICATE;

	size_t buf_len = 0;
	char *buf = get_replication_buffer(&normal, args_leader, &ret_leader, 
	                                   &buf_len);
	ASSERT_NEQ(buf, NULL);

	ASSERT_EQ(write_back_replication_buffer(buf, buf_len, &normal,
	                                        args_follower, &ret_follower),
		  0);
	
	// Arg 1 and 2
	ASSERT_EQ(args_follower[0], 99);
	ASSERT_EQ(args_follower[1], 129);

	// For arg2: pointer location remains the same as before repliation,
	// but buffer contents are updated.
	ASSERT_EQ(args_follower[2], buf2);
	ASSERT_EQ(strcmp((char *)args_follower[2], buf1), 0);

	// For arg3: pointer location remains the same but buffer contents are
	// updated. Furthermore, pointer locations inside the buffer remain
	// the same also, but their pointed-to buffers are also updated.
	ASSERT_EQ(args_follower[3], &s2);
	ASSERT_EQ(((struct simple *)args_follower[3])->a, s1.a);
	ASSERT_EQ(((struct simple *)args_follower[3])->b, buf4);
	ASSERT_EQ(strcmp(((struct simple *)args_follower[3])->b, buf3), 0);
	
	// Return value
	ASSERT_EQ(ret_follower, ret_leader);

	return 0;
}
