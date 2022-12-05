#include "test_suite/test.h"
#include "serialization.h"

#define SERIALIZE_DESERIALIZE_TEST(target, type) {\
	size_t consumed = 0; \
	size_t serialized_len = 0; \
	char *serialized = NULL; \
	serialized = serialize((const char *)&target, type, &serialized_len); \
	ASSERT_NEQ(serialized, NULL); \
	ASSERT(serialized_len > 0); \
	ASSERT_EQ(deserialize_in_place(serialized, type, &consumed), \
	          sizeof(target)); \
	ASSERT_EQ(consumed, serialized_len); \
	ASSERT_EQ(*(typeof(target) *)serialized, target); \
	free(serialized); \
} 

TEST(serialize_deserialize_ints)
{
	long test1 = 0xF00BEEFF00BEEF;
	int test2 = 0xF00BEEF;
	short test3 = 0xBEEF;
	char test4 = 0xBA;
	struct type test1_type = {IMMEDIATE, .immediate = {sizeof(long)} };
	struct type test2_type = {IMMEDIATE, .immediate = {sizeof(int)} };
	struct type test3_type = {IMMEDIATE, .immediate = {sizeof(short)} };
	struct type test4_type = {IMMEDIATE, .immediate = {sizeof(char)} };

	SERIALIZE_DESERIALIZE_TEST(test1, &test1_type);
	SERIALIZE_DESERIALIZE_TEST(test2, &test2_type);
	SERIALIZE_DESERIALIZE_TEST(test3, &test3_type);
	SERIALIZE_DESERIALIZE_TEST(test4, &test4_type);

	return 0;
}

#define SERIALIZE_DESERIALIZE_PTR_TEST(target, type) {\
	size_t consumed = 0; \
	size_t serialized_len = 0; \
	char *serialized = NULL; \
	serialized = serialize((const char *)&target, type, &serialized_len); \
	ASSERT_NEQ(serialized, NULL); \
	ASSERT(serialized_len > 0); \
	ASSERT_EQ(deserialize_in_place(serialized, type, &consumed), \
	          sizeof(target)); \
	ASSERT_EQ(consumed, serialized_len); \
	ASSERT_EQ(**(typeof(target) *)serialized, *target); \
	free(serialized); \
} 

TEST(serialize_deserialize_ptrs)
{
	long target1 = 0xCAFEBABE;
	const char target2[] = "Hello, World.\n";
	long *test1 = &target1;
	const char *test2 = target2;
	struct type target1_type = {IMMEDIATE, .immediate = {sizeof(target1)}};
	struct type target2_type = {BUFFER, .buffer = {sizeof(target2)}};
	struct type test1_type = {POINTER, .pointer = {&target1_type}};
	struct type test2_type = {POINTER, .pointer = {&target2_type}};

	SERIALIZE_DESERIALIZE_PTR_TEST(test1, &test1_type);
	SERIALIZE_DESERIALIZE_PTR_TEST(test2, &test2_type);

	return 0;
}

TEST(serialize_structs_with_ptrs)
{

	struct test_struct_1 {
		char *bufptr; // fixed size 8
		struct test_struct_1 *sptr;
	};
	struct type buf_type = {BUFFER, .buffer = {8}};
	struct type bufptr_type = {POINTER, .pointer = {&buf_type}};
	struct type ts1_type;
	struct type ts1_ptr_type = {POINTER, .pointer = {&ts1_type}};
	struct buffer_content ts1_references[] = {
		{0, &bufptr_type},
		{sizeof(char *), &ts1_ptr_type}
	};
	ts1_type.kind = BUFFER;
	ts1_type.buffer.length = sizeof(struct test_struct_1);
	ts1_type.buffer.n_references = sizeof(ts1_references)/sizeof(ts1_references[0]);
	ts1_type.buffer.references = ts1_references;

	char buf1[] = "1234567";
	char buf2[] = "8912345";
	char buf3[] = "abcdefg";
	struct test_struct_1 ts3 = { buf3, NULL };
	struct test_struct_1 ts2 = { buf2, &ts3 };
	struct test_struct_1 ts1 = { buf1, &ts2 };

	size_t consumed = 0; 
	size_t serialized_len = 0; 
	char *serialized = NULL; 
	serialized = serialize((const char *)&ts1, &ts1_type, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT(serialized_len > 0);
	ASSERT_EQ(deserialize_in_place(serialized, &ts1_type, &consumed), 
	          sizeof(ts1));
	ASSERT_EQ(consumed, serialized_len);
	ASSERT_NEQ(serialized, &ts1);
	struct test_struct_1 *deserialized = (struct test_struct_1 *)serialized;
	ASSERT_EQ(strcmp(buf1, deserialized->bufptr), 0);
	ASSERT_EQ(strcmp(buf2, deserialized->sptr->bufptr), 0);
	ASSERT_EQ(strcmp(buf3, deserialized->sptr->sptr->bufptr), 0);
	free(serialized); \

}

