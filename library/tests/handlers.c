#include <sys/uio.h>

#include "test_suite/test.h"
#include "environment.h"
#include "serialization.h"
#include "handlers.h"
#include "handler_table.h"

TEST(writev)
{
	char buf1[] = "Hello, World.\n";
	char buf2[] = "Foo? Bar!";
	char buf3[] = "!!!\n";
	struct iovec iovecs[] = {
		(struct iovec){buf1, sizeof(buf1)},
		(struct iovec){buf2, sizeof(buf2)},
		(struct iovec){buf3, sizeof(buf3)}
	};

	size_t serialized_len[3] = {};
	size_t deserialized_len[3] = {};
	char *serialized[3] = {};

	long args[N_SYSCALL_ARGS] = {
		1,
		(long)iovecs,
		3
	};
	struct normalized_args normal = {};
	normal.args[0] = args[0];
	normal.args[1] = args[1];
	normal.args[2] = args[2];
	struct environment env = {};
	const struct syscall_handler *handler = get_handler(__NR_writev);

	ASSERT_NEQ(handler, NULL);

	SYSCALL_NORMALIZE_ARGS(writev)(&env, &normal);
	ASSERT_EQ(normal.arg_types[0].kind, DESCRIPTOR);
	ASSERT_EQ(normal.arg_types[1].kind, POINTER);
	ASSERT_EQ(normal.arg_types[2].kind, IMMEDIATE);

	serialized[0] = serialize((const char *)&args[0], &normal.arg_types[0], &serialized_len[0]);
	ASSERT(serialized_len[0] > 0);
	ASSERT_NEQ(serialized[0], NULL);

	serialized[1] = serialize((const char *)&args[1], &normal.arg_types[1], &serialized_len[1]);
	ASSERT(serialized_len[1] > 0);
	ASSERT_NEQ(serialized[1], NULL);
	
	serialized[2] = serialize((const char *)&args[2], &normal.arg_types[2], &serialized_len[2]);
	ASSERT(serialized_len[2] > 0);
	ASSERT_NEQ(serialized[2], NULL);

	deserialized_len[0] = deserialize_in_place(serialized[0], &normal.arg_types[0]);
	ASSERT_EQ(deserialized_len[0], serialized_len[0]);
	ASSERT_EQ(*(int *)serialized[0], args[0]);

	deserialized_len[1] = deserialize_in_place(serialized[1], &normal.arg_types[1]);
	ASSERT_EQ(deserialized_len[1], serialized_len[1]);
	struct iovec *deserialized = *(struct iovec **)serialized[1];
	ASSERT_EQ(deserialized[0].iov_len, iovecs[0].iov_len);
	ASSERT_EQ(deserialized[1].iov_len, iovecs[1].iov_len);
	ASSERT_EQ(deserialized[2].iov_len, iovecs[2].iov_len);
	ASSERT_EQ(strcmp(deserialized[0].iov_base, iovecs[0].iov_base), 0);
	ASSERT_EQ(strcmp(deserialized[1].iov_base, iovecs[1].iov_base), 0);
	ASSERT_EQ(strcmp(deserialized[2].iov_base, iovecs[2].iov_base), 0);

	deserialized_len[2] = deserialize_in_place(serialized[2], &normal.arg_types[2]);
	ASSERT_EQ(deserialized_len[2], serialized_len[2]);
	ASSERT_EQ(*(int *)serialized[2], args[2]);

	return 0;
}
