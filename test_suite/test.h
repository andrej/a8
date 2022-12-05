#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include "test_config.h"

typedef int (* test_fun_t)(void);
struct test {
	test_fun_t fun;
	const char *name;
	const char *file;
}
// On x86_64, the linker appears to add some padding to each test function
// in our array ... we hence must make the struct size reflect that so our
// code does not break.
// TODO: figure out how to control linker padding
__attribute__ ((aligned (64)));

extern struct test __tests_start;
extern struct test __tests_end;

#define TEST(name) \
	int _test_##name(void); \
	const char __test_ ## name ## _name[] = #name; \
	const char __test_ ## name ## _file[] = (__FILE__); \
	struct test __attribute__((section("tests"))) __test_ ## name = { \
		&_test_ ## name, \
		__test_ ## name ## _name, \
		__test_ ## name ## _file \
	}; \
	extern int _test_##name()

#define ASSERT(cond) \
	if(!(cond)) { \
		printf("\n" __FILE__ ": %d: " #cond "\n", __LINE__); \
		return 1; \
	}

#define ASSERT_REL(l, r, l_s, r_s, rel, inv_rel_s) { \
	long long l_v = (long long)(l); \
	long long r_v = (long long)(r); \
	if(!(l_v rel r_v)) { \
		printf("\n" __FILE__ ": %d: " l_s " (%lld) " inv_rel_s \
		       " (%lld) " r_s "\n", __LINE__, l_v, r_v); \
		return 1; \
	} \
}

#define ASSERT_EQ(l, r) ASSERT_REL((l), (r), #l, #r, ==, "!=")
#define ASSERT_NEQ(l, r) ASSERT_REL((l), (r), #l, #r, !=, "==")

#define MOCK(return_type, name, ...) return_type name(__VA_ARGS__)

#define TEST_TRY_OR_RETURN(x, ret) { \
	int s = (x); \
	if(0 != s) { \
		fprintf(stderr, __FILE__ ": %d: " #x ": %d %s\n", s, __LINE__,\
		        strerror(s)); \
		return ret; \
	} \
}

/* ************************************************************************** *
 * PARALLELISM                                                                *
 * ************************************************************************** */
#if !ENABLE_PARALLELISM
#define PARALLEL_TEST(name, nthreads) int _discard_##name() 
#else
#include "parallel_test.h"
#endif

#endif 
