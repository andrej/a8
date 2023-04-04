#include "mocks.h"
#include "test_suite/test.h"
#include "../include/util.h"

char *printed = NULL;
MOCK(int, printk, const char *fmt, ...)
{
	printed = (char *)fmt;
	return 0;
}

/*
The following test won't run until we find a way to mock copy_from_user.

TEST(hash_user_region)
{
	char testbuf[] = "Hello, World.\n";
	char testbuf2[] = "Halli Hallo.\n";
	u64 a = 0;
	u64 b = 0;
	ASSERT_NEQ(a = hash_user_region(testbuf, ((char*)testbuf)+sizeof(testbuf)), 0);
	ASSERT_NEQ(b = hash_user_region(testbuf2, ((char*)testbuf2)+sizeof(testbuf2)), 0);
	ASSERT_NEQ(a, b);
	return 0;
}*/

TEST(try) 
{
	int y = 0;
	printed = NULL;
	TRY(0, y = 2);
	ASSERT(y == 0);
	ASSERT(printed == NULL);
	printed = NULL;
	TRY(1, y = 1);
	ASSERT(y == 1);
	ASSERT(printed != NULL);
	return 0;
}

TEST(line_length)
{
	const char buf[] = "123\n"
	"\n"
	"123456789\n"
	"1\n"
	"12";
	const char buf2[] = {'1', '2', '3', '\n', '4'};
	const char buf3[] = "";
	size_t consumed = 0;
	ASSERT((consumed = line_length(buf, sizeof(buf))) == 4);
	ASSERT((consumed += line_length(buf + consumed, sizeof(buf) - consumed)) == 5);
	ASSERT((consumed += line_length(buf + consumed, sizeof(buf) - consumed)) == 15);
	ASSERT((consumed += line_length(buf + consumed, sizeof(buf) - consumed)) == 17);
	ASSERT((consumed += line_length(buf + consumed, sizeof(buf) - consumed)) == 20); // includes terminating null
	ASSERT((consumed += line_length(buf + consumed, sizeof(buf) - consumed)) == 20); // includes terminating null
	consumed = 0;
	ASSERT((consumed = line_length(buf2, sizeof(buf2))) == 4);
	ASSERT((consumed += line_length(buf2 + consumed, sizeof(buf2) - consumed)) == 5);
	ASSERT((consumed += line_length(buf2 + consumed, sizeof(buf2) - consumed)) == 5);
	consumed = 0;
	ASSERT((consumed = line_length(buf3, sizeof(buf3))) == 1);
	return 0;
}

MOCK(int, kstrtoint, const char *s, unsigned int base, int *res)
{
	long long tmp = 0;
	if(1 != sscanf(s, "%lld", &tmp)) { 
		return -EINVAL;
	}
	if(tmp != (long long)(int)tmp) {
		return -ERANGE;
	}
	*res = tmp;
	return 0;
}

MOCK(int, kstrtoll, const char *s, unsigned int base, int *res)
{
	long long tmp = 0;
	if(1 != sscanf(s, "%lld", &tmp)) { 
		return -EINVAL;
	}
	*res = tmp;
	return 0;
}

TEST(next_int_line)
{
	const char buf[] = "123\n"
	"\n"
	"678\n"
	"\n"
	"\n"
	"12";
	const char buf2[] = "123\n";
	const char buf3[] = "\n\n\n";
	const char buf4[] = "";
	const char buf5[] = { '\n' };  // no terminating null
	const char buf6[] = { '1', '2', '3' };  // no terminating null
	const char buf7[] = { 'q', '\n' };  // no terminating null
	const char buf8[] = "123\nq";
	size_t consumed = 0;
	int num = 0;
	ASSERT_EQ((consumed = next_int_line(buf + consumed, sizeof(buf) - consumed, &num)), 3);
	ASSERT_EQ(num, 123);
	num = 0;
	ASSERT_EQ((consumed += next_int_line(buf + consumed, sizeof(buf) - consumed, &num)), 8);
	ASSERT_EQ(num, 678);
	num = 0;
	ASSERT_EQ((consumed += next_int_line(buf + consumed, sizeof(buf) - consumed, &num)), 13); // includes terminating null
	ASSERT_EQ(num, 12);
	num = 0;
	ASSERT_EQ(next_int_line(buf + consumed, sizeof(buf) - consumed, &num), 0); 

	consumed = 0;
	num = 0;
	ASSERT_EQ((consumed = next_int_line(buf2 + consumed, sizeof(buf2) - consumed, &num)), 3);
	num = 0;
	ASSERT_EQ(next_int_line(buf2 + consumed, sizeof(buf2) - consumed, &num), 0);
	ASSERT_EQ(num, 0);

	consumed = 0;
	num = 0;
	ASSERT_EQ(next_int_line(buf3, sizeof(buf3), &num), 0);
	ASSERT_EQ(num, 0);

	consumed = 0;
	num = 0;
	ASSERT_EQ(next_int_line(buf4, sizeof(buf4), &num), 0);
	ASSERT_EQ(num, 0);

	consumed = 0;
	num = 0;
	ASSERT_EQ(next_int_line(buf5, sizeof(buf5), &num), 0);
	ASSERT_EQ(num, 0);

	consumed = 0;
	num = 0;
	ASSERT_EQ((consumed = next_int_line(buf6, sizeof(buf6), &num)), 3);
	ASSERT_EQ(num, 123);

	consumed = 0;
	num = 0;
	ASSERT_EQ((consumed = next_int_line(buf7, sizeof(buf7), &num)), -1);
	ASSERT_EQ(num, 0);

	consumed = 0;
	num = 0;
	ASSERT_EQ((consumed = next_int_line(buf8, sizeof(buf8), &num)), 3);
	ASSERT_EQ(num, 123);
	ASSERT_EQ(next_int_line(buf8 + consumed, sizeof(buf8) - consumed, &num), -1);
	ASSERT_EQ(num, 123);

	return 0;
}


// MOCKS for isspace/isdigit not exported from kernel

#define _U	0x01	/* upper */
#define _L	0x02	/* lower */
#define _D	0x04	/* digit */
#define _C	0x08	/* cntrl */
#define _P	0x10	/* punct */
#define _S	0x20	/* white space (space/lf/tab) */
#define _X	0x40	/* hex digit */
#define _SP	0x80	/* hard space (0x20) */

const unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,				/* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,			/* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,				/* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,				/* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,				/* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,				/* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,				/* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,				/* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,		/* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,				/* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,				/* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,				/* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,		/* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,				/* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,				/* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,				/* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,			/* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,			/* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,	/* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,	/* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,	/* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,	/* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,	/* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};	/* 240-255 */
