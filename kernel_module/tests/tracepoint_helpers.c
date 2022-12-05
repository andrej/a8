#include "test_suite/test.h"
#include "mocks.h"
#include "../include/tracepoint_helpers.h"

struct tracepoint dummy_tps[] = {
	{"sys_foo", 0, NULL, NULL, NULL},
	{"sys_bar", 0, NULL, NULL, NULL},
	{"sys_baz", 0, NULL, NULL, NULL},
};

MOCK(void, for_each_kernel_tracepoint,
	void (*fct)(struct tracepoint *tp, void *priv), void *priv)
{
	int i = 0;
	for(i = 0; i < sizeof(dummy_tps) / sizeof(dummy_tps[0]); i++) {
		fct(&dummy_tps[i], priv);
	}
}

TEST(find_tracepoint_by_name)
{
	ASSERT(monmod_find_kernel_tracepoint_by_name("sys_foo") 
	       == &dummy_tps[0]);
	ASSERT(monmod_find_kernel_tracepoint_by_name("sys_bar") 
	       == &dummy_tps[1]);
	ASSERT(monmod_find_kernel_tracepoint_by_name("sys_baz") 
	       == &dummy_tps[2]);
	ASSERT(monmod_find_kernel_tracepoint_by_name("sys_qui") == NULL);
	ASSERT(monmod_find_kernel_tracepoint_by_name(NULL) == NULL);
	return 0;
}

