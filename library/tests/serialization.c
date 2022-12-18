#include "test_suite/test.h"
#include "serialization.h"

#define SERIALIZE_DESERIALIZE_TEST(target, type) {\
	size_t serialized_len = 0; \
	char *serialized = NULL; \
	serialized = serialize((const char *)&target, type, &serialized_len); \
	ASSERT_NEQ(serialized, NULL); \
	ASSERT(serialized_len > 0); \
	ASSERT_EQ(deserialize_in_place(serialized, type), \
	          serialized_len); \
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

TEST(serialize_deserialize_string)
{
	const char *str = "Hello, World";
	const int len = strlen(str);
	struct type test1_type = {STRING};

	size_t serialized_len = 0;
	char *serialized = NULL;
	serialized = serialize((const char *)str, &test1_type, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT(serialized_len > 0);
	ASSERT_EQ(deserialize_in_place(serialized, &test1_type),
	          len+1);
	ASSERT_EQ(strcmp(str, serialized), 0);
	return 0;
}

#define SERIALIZE_DESERIALIZE_PTR_TEST(target, type) {\
	size_t serialized_len = 0; \
	char *serialized = NULL; \
	serialized = serialize((const char *)&target, type, &serialized_len); \
	ASSERT_NEQ(serialized, NULL); \
	ASSERT(serialized_len > 0); \
	ASSERT_EQ(deserialize_in_place(serialized, type), \
	          serialized_len); \
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

TEST(serialize_nullptr)
{
	char *ptr = NULL;
	struct type pointee_type = BUFFER_TYPE(128);
	struct type ptr_type = POINTER_TYPE(&pointee_type);

	char *serialized = NULL;
	size_t serialized_len = 0;
	serialized = serialize(&ptr, &ptr_type, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT_EQ(serialized_len, sizeof(uint64_t));

	ASSERT_EQ(deserialize_in_place(serialized, &ptr_type), serialized_len);
	ASSERT_EQ(*(char **)serialized, NULL);

	return 0;
}

TEST(serialize_simple_buffer_ptr)
{
	struct simple {
		long imm1;
		char *ptr;
		long imm2;
	};

	char charbuf[] = "hi";

	struct simple test = {
		29,
		charbuf,
		888
	};

	/* This should get serialized as:
	   0          8  16   24                32         33  34
	   <BUFFER 29 0  888> <POINTER NON_NULL <BUFFER h  i   \0>>
	*/
	char expected[] = {
		29, 0, 0, 0, 0, 0, 0, 0, // long imm1
		0, 0, 0, 0, 0, 0, 0, 0, // char *ptr
		0x78, 0x3, 0, 0, 0, 0, 0, 0, // long imm2
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // non-null ptr
		104, 105, 0, // h i \0
	};

	struct type charbuf_type = BUFFER_TYPE(sizeof(charbuf));
	struct type charptr_type = POINTER_TYPE(&charbuf_type);
	struct buffer_reference simple_refs[] = {{sizeof(long), &charptr_type}};
	struct type simple_type = BUFFER_TYPE(sizeof(struct simple),
	                                      1,
					      simple_refs);
	
	char *serialized = NULL;
	size_t serialized_len = 0;
	serialized = serialize(&test, &simple_type, &serialized_len);

	ASSERT_NEQ(serialized, NULL);
	ASSERT_EQ(serialized_len, sizeof(expected));
	ASSERT_EQ(memcmp(serialized, expected, sizeof(expected)), 0);

	/* This should get deserialized in place as follows:
	   0          8  16   24                32         33  34
	   <BUFFER 29 0  888> <POINTER NON_NULL <BUFFER h  i   \0>> 
	   <original buffer > <new ptr>          <original buffer>
	   ^          ^        | |               ^
	   |          \_copy_ /  \_______________/
	   buf
	   des
	*/
	ASSERT_EQ(deserialize_in_place(serialized, &simple_type), 
	          serialized_len);
	struct simple *deserialized = (struct simple *)serialized;
	ASSERT_EQ(deserialized->imm1, test.imm1);
	ASSERT_EQ(strcmp(deserialized->ptr, test.ptr), 0);
	ASSERT_EQ(deserialized->imm2, test.imm2);

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
	struct type ts1_type = {};
	struct type ts1_ptr_type = {POINTER, .pointer = {&ts1_type}};
	struct buffer_reference ts1_references[] = {
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

	/* This should be serialized as follows:
	   0x0   0  BUFFER (sz 16)
	            0
	   0x8   8  0
	   0x10  16     |- PTR NON-NULL (sz 8)     30
	   0x18  24     |    |- BUFFER (sz 8) 
	                |       1234567\0       
	   0x20  32     |- PTR NON-NULL (sz 8)     40
	   0x28  40     |- BUFFER (sz 16)
	                   0         
	   0x30  48        0
	   0x38  56        |- PTR NON-NULL (sz 8)   58
	   0x40  64        |  |- BUFFER (sz 8)
	                   |     8912345\0
	   0x48  72        |- PTR NON-NULL (sz 8)   68
	   0x50  80           |- BUFFER (sz 16)
	                         0
	   0x58  88              0
	   0x60  96              |- PTR NON-NULL (sz 8) 80
	   0x68  104             |  |- BUFFER 
	                         |     abcdefg\0
	   0x70  112             |- PTR NULL (sz 8)     90
	   0x78  120
	*/
	const char expected[] = {
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[0] ts1
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[1] ts1
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // POINTER ts1.bufptr
		49, 50, 51, 52, 53, 54, 55, 0, // BUFFER[0] buf1,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // POINTER ts1.sptr
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[0] ts2
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[1] ts2
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // POINTER ts2.bufptr
		56, 57, 49, 50, 51, 52, 53, 0, // BUFFER[0] buf2,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // POINTER ts2.sptr
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[0] ts3
		0, 0, 0, 0, 0, 0, 0, 0,  // BUFFER[1] ts3
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // POINTER ts3.bufptr
		97, 98, 99, 100, 101, 102, 103, 0, // BUFFER[0] buf3
		0, 0, 0, 0, 0, 0, 0, 0 // POINTER ts3.sptr NULL
	};

	size_t consumed = 0; 
	size_t serialized_len = 0; 
	char *serialized = NULL; 
	serialized = serialize((const char *)&ts1, &ts1_type, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT_EQ(serialized_len, sizeof(expected));
	ASSERT_EQ(memcmp(expected, serialized, sizeof(expected)), 0);
	ASSERT_EQ(deserialize_in_place(serialized, &ts1_type), 
	          serialized_len);
	ASSERT_NEQ(serialized, &ts1);
	struct test_struct_1 *deserialized = (struct test_struct_1 *)serialized;
	ASSERT_EQ(strcmp(buf1, deserialized->bufptr), 0);
	ASSERT_EQ(strcmp(buf2, deserialized->sptr->bufptr), 0);
	ASSERT_EQ(strcmp(buf3, deserialized->sptr->sptr->bufptr), 0);
	free(serialized); 
	return 0;
}

TEST(deserialize_overwrite)
{
	struct simple {
		char *ptr1;
		char *ptr2;
		long imm;
	};
	char buf1[] = "Hello,";
	char buf2[] = "World!";

	char buf3[] = "Overwr";
	char buf4[] = "ite!!!";

	struct type buf_type = BUFFER_TYPE(sizeof(buf1));
	struct type buf_ptr_type = POINTER_TYPE(&buf_type);
	struct buffer_reference simple_refs[] = 
		{{            0, &buf_ptr_type},
	         {sizeof(char*), &buf_ptr_type}};
	struct type simple_type = BUFFER_TYPE(sizeof(struct simple),
	                                      2, simple_refs);

	struct simple test = {buf1, buf2, 42};
	struct simple overwrite_this = {buf4, buf3, 22};

	char *serialized = NULL;
	size_t serialized_len = 0;
	serialized = serialize(&test, &simple_type, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT(serialized_len > 0);

	ASSERT_EQ(deserialize_overwrite(serialized, &simple_type, 
	                                &overwrite_this), 
	          serialized_len);
	ASSERT_EQ(overwrite_this.imm, test.imm);
	ASSERT_EQ(overwrite_this.ptr1, buf4);
	ASSERT_EQ(overwrite_this.ptr2, buf3);
	ASSERT_EQ(strcmp(buf1, buf4), 0);
	ASSERT_EQ(strcmp(buf2, buf3), 0);

	return 0;
}

TEST(log_str_of)
{
	const char buf1[] = "Hello, 00000000 World 00000000 "
	                    "Imm: 00000000 Str: 00000000";
	const char buf2[] = {1, 0xba};
	const char buf3[] = "Ignored";
	short imm = 1789;
	const char str[] = "Foo? Bar!";
	const char *inp = buf1;
	*(const char **)(buf1 + 7) = buf2;
	*(const char **)(buf1 + 22) = buf3;
	*(short **)(buf1 + 36) = &imm;
	*(const char **)(buf1 + 50) = str;
	const char expected[] = 
		"POINTER to BUFFER [Hello, <ADDR OF REF 0> World "
		"<ADDR OF REF 1> Imm: <ADDR OF REF 2> Str: <ADDR OF REF 3>\\0]"
		" with <REF 0: POINTER to BUFFER [\\1\\ba]> <REF 1: IGNORE> "
		"<REF 2: POINTER to IMMEDIATE 1789> "
		"<REF 3: POINTER to STRING \"Foo? "
		"Bar!\">";
	char outbuf[2*sizeof(expected)] = {};
	struct type t5 = {STRING};
	struct type t5_ptr = {POINTER, .pointer = {&t5}};
	struct buffer_reference t5r = {50, &t5_ptr};
	struct type t4 = {IMMEDIATE, .immediate = {sizeof(short)}};
	struct type t4_ptr = {POINTER, .pointer = {&t4}};
	struct buffer_reference t4r = {36, &t4_ptr};
	struct type t3 = {IGNORE};
	struct buffer_reference t3r = {22, &t3};
	struct type t2 = {BUFFER, .buffer = {sizeof(buf2)}};
	struct type t2_ptr = {POINTER, .pointer = {&t2}};
	struct buffer_reference t2r = {7, &t2_ptr};
	struct buffer_reference refs[] = {t2r, t3r, t4r, t5r};
	struct type t1 = {BUFFER, .buffer = {sizeof(buf1), 4, refs}};
	struct type t0 = {POINTER, .pointer = {&t1}};

	ASSERT_EQ(
		log_str_of((const char *)&inp, &t0, outbuf, sizeof(outbuf)),
		sizeof(expected)-1
	);
	ASSERT_EQ(strcmp(outbuf, expected), 0);

	return 0;
}

TEST(serialize_deserialize_str)
{
	const char str[] = "Hello, World!";

	size_t serialized_len = 0;
	char *serialized = NULL;
	char des_str[sizeof(str)];

	struct type t = STRING_TYPE();

	serialized = serialize(str, &t, &serialized_len);
	ASSERT_NEQ(serialized, NULL);
	ASSERT_EQ(serialized_len, sizeof(str));

	deserialize_overwrite(serialized, &t, des_str);
	ASSERT_EQ(strcmp(des_str, str), 0);

	return 0;
}
