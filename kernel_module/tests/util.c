#include "mocks.h"
#include "test_suite/test.h"
#include "../include/util.h"

char *printed = NULL;
MOCK(int, printk, const char *fmt, ...)
{
	printed = (char *)fmt;
	return 0;
}

TEST(try) 
{
	printed = NULL;
	int y = 0;
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
	size_t consumed = 0;
	int num = 0;
	ASSERT((consumed = next_int_line(buf + consumed, sizeof(buf) - consumed, &num)) == 4);
	ASSERT(num = 123);
	num = 0;
	ASSERT((consumed += next_int_line(buf + consumed, sizeof(buf) - consumed, &num)) == 9);
	ASSERT(num = 678);
	num = 0;
	ASSERT((consumed += next_int_line(buf + consumed, sizeof(buf) - consumed, &num)) == 14); // includes terminating null
	ASSERT(num = 12);
	num = 0;
	ASSERT(next_int_line(buf + consumed, sizeof(buf) - consumed, &num) == -1); 

	consumed = 0;
	num = 0;
	ASSERT((consumed = next_int_line(buf2 + consumed, sizeof(buf2) - consumed, &num)) == 4);
	num = 0;
	ASSERT(next_int_line(buf2 + consumed, sizeof(buf2) - consumed, &num) == -1);
	ASSERT(num == 0);

	consumed = 0;
	num = 0;
	ASSERT(next_int_line(buf3, sizeof(buf3), &num) == -1);
	return 0;
}
