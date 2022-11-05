#ifndef TEST_H
#define TEST_H

typedef int (* test_fun_t)();
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
	int _test_##name(); \
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

#endif 

#define MOCK(return_type, name, ...) return_type name(__VA_ARGS__)
