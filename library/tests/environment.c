#include "test_suite/test.h"
#include "environment.h"

TEST(environment)
{
	int can1, can3;
	struct environment env = {};
	struct descriptor_info *di = NULL;
	ASSERT_EQ(env.n_descriptors, 0);
	ASSERT_NEQ(di = env_add_local_descriptor(&env, 1, 0, 
	                                         SOCKET_DESCRIPTOR),
		   NULL);
	can1 = env_canonical_fd_for(&env, di);
	di = env_get_local_descriptor_info(&env, 1);
	ASSERT_NEQ(di, NULL);
	//ASSERT_EQ(di->canonical_fd, 0);
	ASSERT_EQ(di->local_fd, 1);
	ASSERT_EQ(di->flags, 0);

	ASSERT_NEQ(env_add_local_descriptor(&env, 2, DI_OPENED_LOCALLY,
	                                    SOCKET_DESCRIPTOR),
		   NULL);
	di = env_get_local_descriptor_info(&env, 2);
	ASSERT_NEQ(di, NULL);
	//ASSERT_EQ(di->canonical_fd, 1);
	ASSERT_EQ(di->local_fd, 2);
	ASSERT_EQ(di->flags, DI_OPENED_LOCALLY);

	ASSERT_NEQ(di = env_add_descriptor(&env, 4, 3, DI_OPENED_ON_LEADER, 
	                                   SOCKET_DESCRIPTOR), 
		   NULL);
	can3 = env_canonical_fd_for(&env, di);
	di = env_get_canonical_descriptor_info(&env, 3);
	ASSERT_NEQ(di, NULL);
	//ASSERT_EQ(di->canonical_fd, 3);
	ASSERT_EQ(di->local_fd, 4);
	ASSERT_EQ(di->flags, DI_OPENED_ON_LEADER);

	ASSERT_EQ(env.n_descriptors, 3);
	ASSERT_NEQ(di = env_get_canonical_descriptor_info(&env, can1), NULL);
	ASSERT_EQ(env_del_descriptor(&env, di), 0);
	ASSERT_EQ(env.n_descriptors, 2);
	ASSERT_EQ(di = env_get_canonical_descriptor_info(&env, can1), NULL);
	ASSERT_NEQ(di = env_get_canonical_descriptor_info(&env, can3), NULL);
	//ASSERT_EQ(di->canonical_fd, 3);
	ASSERT_EQ(di->local_fd, 4);
	ASSERT_EQ(di->flags, DI_OPENED_ON_LEADER);

	return 0;
}

TEST(epoll_infos_list)
{
	struct environment env = {};
	struct epoll_data_info *info = NULL;

	env_init(&env, NULL);
	ASSERT_EQ(0, append_epoll_data_info(&env, 
			(struct epoll_data_info){1, 2, {0x2}}));
	ASSERT_EQ(0, append_epoll_data_info(&env, 
			(struct epoll_data_info){1, 3, {0x2}}));
	ASSERT_EQ(0, append_epoll_data_info(&env, 
			(struct epoll_data_info){2, 3, {0x4}}));
	ASSERT_EQ(0, append_epoll_data_info(&env, 
			(struct epoll_data_info){2, 4, {0x4|0x8}}));
	
	// Find first element
	ASSERT_EQ(1, get_epoll_data_info_for(&env, 1, 2, 0x2)->epfd);
	ASSERT_EQ(2, get_epoll_data_info_for(&env, 1, 2, 0x2)->fd);
	ASSERT_EQ(0x2, get_epoll_data_info_for(&env, 1, 2, 0x2)->data.events);
	// Find second element
	ASSERT_EQ(1, get_epoll_data_info_for(&env, 1, 3, 0x2)->epfd);
	ASSERT_EQ(3, get_epoll_data_info_for(&env, 1, 3, 0x2)->fd);
	// Find third element
	ASSERT_EQ(2, get_epoll_data_info_for(&env, 2, 3, 0x4)->epfd);
	ASSERT_EQ(3, get_epoll_data_info_for(&env, 2, 3, 0x4)->fd);
	// Non-existent element
	ASSERT_EQ(NULL, get_epoll_data_info_for(&env, 2, 3, 0x2));
	// Find fourth element
	ASSERT_EQ(2, get_epoll_data_info_for(&env, 2, 4, 0x4)->epfd);
	ASSERT_EQ(4, get_epoll_data_info_for(&env, 2, 4, 0x8)->fd);

	// Remove third element
	ASSERT_NEQ(NULL, info = get_epoll_data_info_for(&env, 2, 3, 0x4));
	ASSERT_EQ(0, remove_epoll_data_info(&env, info));
	ASSERT_EQ(NULL, info = get_epoll_data_info_for(&env, 2, 3, 0x4));

	// Find and remove fourth element
	ASSERT_NEQ(NULL, info = get_epoll_data_info_for(&env, 2, 4, 0x8));
	ASSERT_EQ(2, info->epfd);
	ASSERT_EQ(4, info->fd);
	ASSERT_EQ(0, remove_epoll_data_info(&env, info));
	ASSERT_EQ(NULL, info = get_epoll_data_info_for(&env, 2, 4, 0x4));
	ASSERT_EQ(NULL, info = get_epoll_data_info_for(&env, 2, 4, 0x8));

	// Find and remove first element
	ASSERT_NEQ(NULL, info = get_epoll_data_info_for(&env, 1, 2, 0x2));
	ASSERT_EQ(0, remove_epoll_data_info(&env, info));
	ASSERT_EQ(NULL, info = get_epoll_data_info_for(&env, 1, 2, 0x2));

	// Find second element (only remaining one)
	ASSERT_NEQ(NULL, info = get_epoll_data_info_for(&env, 1, 3, 0x2));
	ASSERT_EQ(info->epfd, 1);
	ASSERT_EQ(info->fd, 3);

	return 0;
}