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

	struct syscall_info actual_leader = {
		.args = {
			128,
			129,
			(long)buf1,
			(long)&s1
		},
		.ret = 42
	};
	struct syscall_info actual_follower = {
		.args = {
			99,   // replication should ignore this one
			100,  // replication should overwrite this one with 129
			(long)buf2, // replication should overwrite buffer buf1 into 
				// buf2, but leave pointer argument unchanged
			(long)&s2 // replication should overwrite referenced pointer 
				// inside pointed-to struct and update struct fields
		},
		.ret = 12
	};

	struct syscall_info canonical = {};
	memcpy(canonical.args, actual_leader.args, sizeof(canonical.args));

	// Arg 1 type
	struct type arg1_type = IGNORE_TYPE();
	canonical.arg_types[0] = arg1_type;
	canonical.arg_flags[0] = ARG_FLAG_NONE;

	// Arg 2 type
	struct type arg2_type = IMMEDIATE_TYPE(sizeof(long));
	canonical.arg_types[1] = arg2_type;
	canonical.arg_flags[1] = ARG_FLAG_REPLICATE;

	// Arg 3 type
	struct type arg3_buf_type = BUFFER_TYPE(sizeof(buf1));
	struct type arg3_type = POINTER_TYPE(&arg3_buf_type);
	canonical.arg_types[2] = arg3_type;
	canonical.arg_flags[2] = ARG_FLAG_REPLICATE;

	// Arg 4 type
	struct type arg4_buf_ptr_buf_type = BUFFER_TYPE(sizeof(sizeof(buf3)));
	struct type arg4_buf_ptr_type = POINTER_TYPE(&arg4_buf_ptr_buf_type);
	struct buffer_reference arg4_buf_refs[] = {{(void *)&s1.b-(void *)&s1,
	                                           &arg4_buf_ptr_type}};
	struct type arg4_buf_type = BUFFER_TYPE(sizeof(struct simple),
	                                        1, arg4_buf_refs);
	struct type arg4_type = POINTER_TYPE(&arg4_buf_type);
	canonical.arg_types[3] = arg4_type;
	canonical.arg_flags[3] = ARG_FLAG_REPLICATE;

	// Return type
	struct type ret_type = IMMEDIATE_TYPE(sizeof(long));
	canonical.ret_type = ret_type;
	canonical.ret_flags = ARG_FLAG_REPLICATE;

	size_t buf_len = 0;
	char *buf = get_replication_buffer(&actual_leader, &canonical, 
	                                   &buf_len);
	ASSERT_NEQ(buf, NULL);

	ASSERT_EQ(write_back_replication_buffer(&actual_follower, &canonical,
	                                        buf, buf_len),
		  0);
	
	// Arg 1 and 2
	ASSERT_EQ(actual_follower.args[0], 99);
	ASSERT_EQ(actual_follower.args[1], 129);

	// For arg2: pointer location remains the same as before repliation,
	// but buffer contents are updated.
	ASSERT_EQ(actual_follower.args[2], buf2);
	ASSERT_EQ(strcmp((char *)actual_follower.args[2], buf1), 0);

	// For arg3: pointer location remains the same but buffer contents are
	// updated. Furthermore, pointer locations inside the buffer remain
	// the same also, but their pointed-to buffers are also updated.
	ASSERT_EQ(actual_follower.args[3], &s2);
	ASSERT_EQ(((struct simple *)actual_follower.args[3])->a, s1.a);
	ASSERT_EQ(((struct simple *)actual_follower.args[3])->b, buf4);
	ASSERT_EQ(strcmp(((struct simple *)actual_follower.args[3])->b, buf3), 0);
	
	// Return value
	ASSERT_EQ(actual_follower.ret, actual_leader.ret);

	return 0;
}
