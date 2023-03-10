#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "test_suite/test.h"
#include "communication.h"

static inline struct sockaddr_in get_test_sockaddr(in_port_t port)
{
	return (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(port)
	};
}

PARALLEL_TEST(simple_conn_setup_teardown, 2)
{
	const int port1 = 3729;
	const int port2 = 3730;
	struct sockaddr_in addrs[] = {
		get_test_sockaddr(3729),
		get_test_sockaddr(3730)
	};
	struct communicator comm;
	ON_THREAD(0) {
		ASSERT_EQ(comm_init(&comm, 0, (struct sockaddr *)&addrs[0]), port1);
	}
	BARRIER();
	ON_THREAD(1) {
		ASSERT_EQ(comm_init(&comm, 1, (struct sockaddr *)&addrs[1]), port2);
		ASSERT_EQ(comm_connect(&comm, 0, (struct sockaddr *)&addrs[0]), 0);
	}
	BARRIER(); // accept() (in thread 0) will block if no connect() (from thread 1) issued
	ON_THREAD(0) {
		ASSERT_EQ(comm_connect(&comm, 1, (struct sockaddr *)&addrs[1]), 0);
	}
	BARRIER();
	ASSERT_EQ(comm_destroy(&comm), 0);
	return 0;
}

PARALLEL_TEST(failing_conn_setup, 2)
{
	/* This test is supposed to fail because we are trying to connect in 
	   the wrong order: Lower-ID nodes must connect first, since they will
	   act as server. */
	const int port1 = 3727;
	const int port2 = 3728;
	struct sockaddr_in addrs[] = {
		get_test_sockaddr(port1),
		get_test_sockaddr(port2)
	};
	struct communicator comm;
	ON_THREAD(1) {
		ASSERT_EQ(comm_init(&comm, 1, (struct sockaddr *)&addrs[1]), port1);
		ASSERT_NEQ(comm_connect(&comm, 0, (struct sockaddr *)&addrs[0]), 0);
	}
	BARRIER();
	ON_THREAD(0) {
		ASSERT_EQ(comm_init(&comm, 0, (struct sockaddr *)&addrs[0]), port2);
	}
	BARRIER();
	ASSERT_EQ(comm_destroy(&comm), 0);
	return 0;
}

PARALLEL_TEST(conn_setup_send_teardown, 3)
{
	const int ports[] = {
		3731,
		3732,
		3733
	};
	struct sockaddr_in addrs[] = {
		get_test_sockaddr(ports[0]),
		get_test_sockaddr(ports[1]),
		get_test_sockaddr(ports[2])
	};
	struct communicator comm;
	char recvbuf[128];
	size_t recvn;
	long recvlong;
	const char test0[] = "hello";
	long test1 = 0xDEAD;
	long test2 = 0xBEEF;
	long test3 = -42;

	ON_THREAD(0) {
		ASSERT_EQ(comm_init(&comm, 0, (struct sockaddr *)&addrs[0]), ports[0]);
	}
	ON_THREAD(1) {
		ASSERT_EQ(comm_init(&comm, 1, (struct sockaddr *)&addrs[1]), ports[1]);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_init(&comm, 2, (struct sockaddr *)&addrs[2]), ports[2]);
	}
	// TODO: tests to make sure we cannot double-initialize
	BARRIER();  // make sure all servers are started before we attempt to connect

	// 0 <--> 1
	ON_THREAD(0) {
		ASSERT_EQ(comm_connect(&comm, 1, (struct sockaddr *)&addrs[1]), 0);
	}
	ON_THREAD(1) {
		ASSERT_EQ(comm_connect(&comm, 0, (struct sockaddr *)&addrs[0]), 0);
	}
	// 0 <--> 2
	ON_THREAD(0) {
		ASSERT_EQ(comm_connect(&comm, 2, (struct sockaddr *)&addrs[2]), 0);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_connect(&comm, 0, (struct sockaddr *)&addrs[0]), 0);
	}
	// 1 <--> 2
	ON_THREAD(1) {
		ASSERT_EQ(comm_connect(&comm, 2, (struct sockaddr *)&addrs[2]), 0);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_connect(&comm, 1, (struct sockaddr *)&addrs[1]), 0);
	}
	// TODO: tests to make sure we cannot double-connect

	BARRIER();

	// 0 -- "hello" --> 1
	ON_THREAD(0) {
		ASSERT_EQ(comm_send(&comm, 1, sizeof(test0), test0), 0);
	}
	ON_THREAD(1) {
		recvn = sizeof(recvbuf); 
		ASSERT_EQ(comm_receive(&comm, 0, &recvn, recvbuf), 0);
		ASSERT_EQ(recvn, sizeof(test0));
		ASSERT(strncmp(test0, recvbuf, sizeof(test0)) == 0);
	}

	// 1 --> 0xDEAD --> 2
	ON_THREAD(1) {
		ASSERT_EQ(comm_send_p(&comm, 2, test1), 0);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_receive_p(&comm, 1, &recvlong), 0);
		ASSERT_EQ(recvlong, test1);
	}
	// 2 --> 0xBEEF --> 0
	ON_THREAD(2) {
		ASSERT_EQ(comm_send_p(&comm, 0, test2), 0);
	}
	ON_THREAD(0) {
		ASSERT_EQ(comm_receive_p(&comm, 2, &recvlong), 0);
		ASSERT_EQ(recvlong, test2);
	}

	ASSERT_EQ(comm_destroy(&comm), 0);
	return 0;
}

PARALLEL_TEST(comm_broadcast, 3)
{
	const int ports[] = {
		3734,
		3735,
		3736
	};
	struct sockaddr_in addrs[] = {
		get_test_sockaddr(ports[0]),
		get_test_sockaddr(ports[1]),
		get_test_sockaddr(ports[2])
	};
	struct communicator comms[3] = {};

	char recvbuf[128];
	size_t recvn;
	const char testbuf[] = "Hello, World.\n";

	ON_THREAD(0) {
		ASSERT_EQ(comm_init(&comms[0], 0, (struct sockaddr *)&addrs[0]), ports[0]);
	}
	ON_THREAD(1) {
		ASSERT_EQ(comm_init(&comms[1], 1, (struct sockaddr *)&addrs[1]), ports[1]);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_init(&comms[2], 2, (struct sockaddr *)&addrs[2]), ports[2]);
	}

	BARRIER();

	// 0 --> 1
	//   \-> 2
	ON_THREAD(0) {
		ASSERT_EQ(comm_connect(&comms[0], 1, (struct sockaddr *)&addrs[1]), 0);
		ASSERT_EQ(comm_connect(&comms[0], 2, (struct sockaddr *)&addrs[2]), 0);
	}

	// 1 --> 0
	ON_THREAD(1) {
		ASSERT_EQ(comm_connect(&comms[1], 0, (struct sockaddr *)&addrs[0]), 0);
	}

	// 2 --> 0
	ON_THREAD(2) {
		ASSERT_EQ(comm_connect(&comms[2], 0, (struct sockaddr *)&addrs[0]), 0);
	}

	BARRIER();
	
	// 1 -- "Hello, World.\n" --> 0
	ON_THREAD(1) {
		ASSERT_EQ(comm_broadcast(&comms[1], sizeof(testbuf), testbuf), 0);
	}
	recvn = sizeof(recvbuf);
	ON_THREAD(0) {
		ASSERT_EQ(comm_receive(&comms[0], 1, &recvn, recvbuf), 0);
		ASSERT_EQ(recvn, sizeof(testbuf));
		ASSERT_EQ(strncmp(testbuf, recvbuf, sizeof(testbuf)), 0);
	}

	// 0 -- "Hello, World.\n" --> 1
	//                        \-> 2
	ON_THREAD(0) {
		ASSERT_EQ(comm_broadcast(&comms[0], sizeof(testbuf), testbuf), 0);
	}
	recvn = sizeof(recvbuf);
	ON_THREAD(1) {
		ASSERT_EQ(comm_receive(&comms[1], 0, &recvn, recvbuf), 0);
		ASSERT_EQ(recvn, sizeof(testbuf));
		ASSERT_EQ(strncmp(testbuf, recvbuf, sizeof(testbuf)), 0);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_receive(&comms[2], 0, &recvn, recvbuf), 0);
		ASSERT_EQ(recvn, sizeof(testbuf));
		ASSERT_EQ(strncmp(testbuf, recvbuf, sizeof(testbuf)), 0);
	}

	ON_THREAD(0) {
		ASSERT_EQ(comm_destroy(&comms[0]), 0);
	}
	ON_THREAD(1) {
		ASSERT_EQ(comm_destroy(&comms[1]), 0);
	}
	ON_THREAD(2) {
		ASSERT_EQ(comm_destroy(&comms[2]), 0);
	}

	return 0;
}

PARALLEL_TEST(recover_from_missized_message_buffer_receive, 2)
{
	char test[] = "This is way longer than three characters.\n";
	char recvbuf1[3] = {};
	char recvbuf2[sizeof(test)] = {};
	size_t recvn;
	
	const int ports[] = {
		45321,
		45322
	};
	struct sockaddr_in addrs[] = {
		get_test_sockaddr(ports[0]),
		get_test_sockaddr(ports[1])
	};
	struct communicator comm;
	ASSERT_EQ(comm_init(&comm, THREAD_NUM(), (struct sockaddr *)&addrs[THREAD_NUM()]), ports[THREAD_NUM()]);
	BARRIER();
	const int other_id = (THREAD_NUM()+1)%2;
	ASSERT_EQ(comm_connect(&comm, other_id, (struct sockaddr *)&addrs[other_id]), 0);
	BARRIER();
	// First, send large buffer and receive into small buffer.
	ON_THREAD(0) {
		ASSERT_EQ(comm_send(&comm, 1, sizeof(test), test), 0);
	}
	ON_THREAD(1) {
		recvn = sizeof(recvbuf1);
		ASSERT_EQ(comm_receive_partial(&comm, 0, &recvn, recvbuf1), 0);
		// Size should show original message size, even though less
		// was written.
		ASSERT_EQ(recvn, sizeof(test));
		// Make sure only recvbuf1 was written to, no overflow.
		ASSERT_EQ(strncmp(recvbuf1, test, 3), 0);
		ASSERT_EQ(recvbuf2[0], 0);
	}

	// Second, send large buffer and receive into large buffer.
	// This should be unaffected by previous too large buffer.
	ON_THREAD(0) {
		ASSERT_EQ(comm_send(&comm, 1, sizeof(test), test), 0);
	}
	ON_THREAD(1) {
		recvn = sizeof(recvbuf2);
		ASSERT_EQ(comm_receive_partial(&comm, 0, &recvn, recvbuf2), 0);
		ASSERT_EQ(recvn, sizeof(test));
		ASSERT_EQ(strncmp(recvbuf2, test, sizeof(recvbuf2)), 0);
	}

	ASSERT_EQ(comm_destroy(&comm), 0);
	return 0;
}

const int nnodes = 8;
PARALLEL_TEST(all_agree_many_nodes, nnodes)
{
	const int leader = 3;
	const int disagreeable = 4 % nnodes;
	const char test1[] = "Hello, World.\n";
	const char test2[] = "Foo? Bar!\n";
	const char test3[] = {0x0, 0xF0, 0xBA};

	const in_port_t port_base = 14983;
	struct sockaddr_in addrs[nnodes];
	for(int i = 0; i < nnodes; i++) {
		addrs[i] = get_test_sockaddr(port_base + i);
	}

	// Set everyone up
	struct communicator comm;
	for(int i = 0; i < nnodes; i++) {
		ON_THREAD(i) {
			ASSERT_EQ(comm_init(&comm, i, (struct sockaddr *)&addrs[i]), port_base + i);
		}
	}
	BARRIER();

	// Connect everyone except leader to leader and one other neighbor node
	// i --> leader
	//   \-> i+1
	for(int i = 0; i < nnodes; i++) {
		if(i == leader) {
			continue;
		}
		const int j = (i+1)%nnodes;
		ON_THREAD(i) {
			ASSERT_EQ(comm_connect(&comm, leader, (struct sockaddr *)&addrs[leader]), 0);
		}
		if(j != leader) {
			ON_THREAD(j) {
				ASSERT_EQ(comm_connect(&comm, i, (struct sockaddr *)&addrs[i]), 0);
			}
			ON_THREAD(i) {
				ASSERT_EQ(comm_connect(&comm, j, (struct sockaddr *)&addrs[j]), 0);
			}
		}
	}
	// Connect leader to everyone
	ON_THREAD(leader) { 
		for(int i = 0; i < nnodes; i++) {
			if(i == leader) {
				continue;
			}
			ASSERT_EQ(comm_connect(&comm, i, (struct sockaddr *)&addrs[i]), 0);
		}
	}

	// First, one where everyone should agree
	ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test1), test1), 1);

	// Leader disagrees
	ON_THREAD(leader) {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test1), test1), 0);
	} else {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test2), test2), 0);
	}

	// Disagreeable node disagress
	ON_THREAD(disagreeable) {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test1), test1), 0);
	} else {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test2), test2), 0);
	}

	// Can we still agree?
	ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test3), test3), 1);

	// Disagree with different sizes
	ON_THREAD(disagreeable) {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test3), test3), 0);
	} else {
		ASSERT_EQ(comm_all_agree(&comm, leader, sizeof(test1), test1), 0);
	}

	ASSERT_EQ(comm_destroy(&comm), 0);

	return 0;
}
