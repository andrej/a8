#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include "test_config.h"

#if ENABLE_PARALLELISM
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#endif

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

#define ASSERT_EQ(l, r) { \
	long long l_v = (l); \
	long long r_v = (r); \
	if(l_v != r_v) { \
		printf("\n" __FILE__ ": %d: " #l " (%lld) != (%lld) " #r "\n", \
		       __LINE__, l_v, r_v); \
		return 1; \
	} \
}

#define MOCK(return_type, name, ...) return_type name(__VA_ARGS__)


/* ************************************************************************** *
 * PAPRALLELISM                                                               *
 * ************************************************************************** */
#if !ENABLE_PARALLELISM
#define PARALLEL_TEST(name, nthreads) int _discard_##name() 
#else

struct _test_main_thread_info {
	pthread_barrier_t barrier;
	pthread_mutex_t done_mutex;
	pthread_cond_t done_cond;
	int done_thread_num;
};

struct _test_thread_info {
	struct _test_main_thread_info *main_info;
	pthread_t thread_id;
	int thread_num;
	int is_done;
};

#define PARALLEL_TEST(name, nthreads) \
	static void *_test_##name##_thread(void *arg); \
	static inline int _test_##name##_thread_inner(struct _test_thread_info \
	                                              *tinfo); \
	TEST(name) { \
		int s; \
		pthread_attr_t attr; \
		struct _test_main_thread_info minfo = {}; \
		minfo.done_thread_num = -1; \
		if(0 != pthread_attr_init(&attr)) { \
			perror("pthread_attr_init"); \
			return 1; \
		} \
		if(0 != pthread_barrier_init(&minfo.barrier, NULL, nthreads)) {\
			perror("pthread_barrier_init"); \
			return 1; \
		} \
		if(0 != pthread_mutex_init(&minfo.done_mutex, NULL)) { \
			perror("pthread_mutex_init"); \
			return 1; \
		} \
		if(0 != pthread_cond_init(&minfo.done_cond, NULL)) { \
			perror("pthread_cond_init"); \
			return 1; \
		} \
		struct _test_thread_info tinfo[nthreads]; \
		for(int i = 0; i < nthreads; i++) { \
			tinfo[i].thread_num = i; \
			tinfo[i].main_info = &minfo; \
			tinfo[i].is_done = 0; \
			if(0 != pthread_create(&tinfo[i].thread_id, &attr, \
			                       &_test_##name##_thread, \
					       &tinfo[i])) { \
				perror("pthread_create"); \
				return 1; \
			} \
		} \
		int ret = 0; \
		for(int i = 0; i < nthreads; i++) { \
			void *res; \
			int done_thread_num; \
			if(0 != pthread_mutex_lock(&minfo.done_mutex)){ \
				perror("pthread_mutex_lock"); \
				return 1; \
			} \
			while(0 > minfo.done_thread_num) { \
				if(0 != pthread_cond_wait(&minfo.done_cond,  \
							&minfo.done_mutex)) { \
					perror("pthread_cond_wait"); \
					return 1; \
				} \
			} \
			done_thread_num = minfo.done_thread_num; \
			minfo.done_thread_num = -1; \
			if(0 != pthread_mutex_unlock(&minfo.done_mutex)) { \
				perror("pthread_mutex_unlock"); \
				return 1; \
			} \
			if(0 != pthread_join(tinfo[done_thread_num].thread_id, \
			                     &res)) { \
				perror("pthread_join"); \
			} \
			tinfo[done_thread_num].is_done = 1; \
			/* If one thread failed the test, cancel the others.*/ \
			if(NULL != res) { \
				for(int j = 0; i < nthreads; j++) { \
					if(tinfo[j].is_done) { \
						continue; \
					} \
					if(0 != pthread_cancel(tinfo[j] \
					                       .thread_id)) { \
						perror("pthread_cancel"); \
						return 1; \
					} \
				} \
				ret = 2; \
				break; \
			} \
		} \
		if(0 != pthread_attr_destroy(&attr)) { \
			perror("pthread_attr_destroy"); \
			return 1; \
		} \
		if(0 != pthread_barrier_destroy(&minfo.barrier)) { \
			perror("pthread_barrier_destroy"); \
			return 1; \
		} \
		if(0 != pthread_mutex_destroy(&minfo.done_mutex)) { \
			perror("pthread_mutex_destroy"); \
			return 1; \
		} \
		if(0 != pthread_cond_destroy(&minfo.done_cond)) { \
			perror("pthread_cond_destroy"); \
			return 1; \
		} \
		return ret; \
	} \
	static void *_test_##name##_thread(void *arg) { \
		int ret; \
		struct _test_thread_info *tinfo = arg; \
		ret = _test_##name##_thread_inner(tinfo); \
		if(0 != pthread_mutex_lock(&tinfo->main_info->done_mutex)) { \
			perror("pthread_mutex_lock"); \
			return (void *)1L; \
		} \
		tinfo->main_info->done_thread_num = tinfo->thread_num; \
		if(0 != pthread_cond_signal(&tinfo->main_info->done_cond)) { \
			perror("pthread_cond_signal"); \
			return (void *)1L; \
		} \
		if(0 != pthread_mutex_unlock(&tinfo->main_info->done_mutex)) { \
			perror("pthread_mutex_unlock"); \
			return (void *)1L; \
		} \
		return (void *)(long)ret; \
	} \
	static inline int _test_##name##_thread_inner(struct _test_thread_info \
	                                              *tinfo)

#define ON_THREAD(n) if(tinfo->thread_num == n)

#define BARRIER() ({ \
	int s; \
	s = pthread_barrier_wait(tinfo->barrier); \
	if(0 != s && PTHREAD_BARRIER_SERIAL_THREAD != s) { \
		perror("pthread_barrier_wait"); \
		return 1; \
	} \
})

#endif

#endif 
