#include "test_suite/test.h"
#include "environment.h"

TEST(environment)
{
	struct environment env = {};
	struct descriptor_info *di = NULL;
	ASSERT_EQ(env.n_descriptors, 0);
	ASSERT_EQ(env_add_local_descriptor(&env, 1, 0), 0);
	di = env_get_local_descriptor_info(&env, 1);
	ASSERT_NEQ(di, NULL);
	ASSERT_EQ(di->canonical_fd, 0);
	ASSERT_EQ(di->local_fd, 1);
	ASSERT_EQ(di->flags, 0);

	ASSERT_EQ(env_add_local_descriptor(&env, 2, DI_OPENED_LOCALLY), 1);
	di = env_get_local_descriptor_info(&env, 2);
	ASSERT_NEQ(di, NULL);
	ASSERT_EQ(di->canonical_fd, 1);
	ASSERT_EQ(di->local_fd, 2);
	ASSERT_EQ(di->flags, DI_OPENED_LOCALLY);

	ASSERT_EQ(env_add_descriptor(&env, 4, 3, DI_OPENED_ON_LEADER), 0);
	di = env_get_canonical_descriptor_info(&env, 3);
	ASSERT_NEQ(di, NULL);
	ASSERT_EQ(di->canonical_fd, 3);
	ASSERT_EQ(di->local_fd, 4);
	ASSERT_EQ(di->flags, DI_OPENED_ON_LEADER);

	ASSERT_EQ(env.n_descriptors, 3);
	ASSERT_NEQ(di = env_get_canonical_descriptor_info(&env, 1), NULL);
	ASSERT_EQ(env_del_descriptor(&env, di), 0);
	ASSERT_EQ(env.n_descriptors, 2);
	ASSERT_EQ(di = env_get_canonical_descriptor_info(&env, 1), NULL);
	ASSERT_NEQ(di = env_get_canonical_descriptor_info(&env, 3), NULL);
	ASSERT_EQ(di->canonical_fd, 3);
	ASSERT_EQ(di->local_fd, 4);
	ASSERT_EQ(di->flags, DI_OPENED_ON_LEADER);

	return 0;
}
