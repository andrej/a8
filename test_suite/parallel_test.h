#ifndef PARALLEL_TEST_H
#define PARALLEL_TEST_H

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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
		TEST_TRY_OR_RETURN(pthread_attr_init(&attr), 1); \
		TEST_TRY_OR_RETURN(pthread_barrier_init(&minfo.barrier, \
		                                        NULL, nthreads), 1); \
		TEST_TRY_OR_RETURN(pthread_mutex_init(&minfo.done_mutex, NULL),\
		                   1); \
		TEST_TRY_OR_RETURN(pthread_cond_init(&minfo.done_cond, NULL), \
		                   1);\
		struct _test_thread_info tinfo[nthreads]; \
		for(int i = 0; i < nthreads; i++) { \
			tinfo[i].thread_num = i; \
			tinfo[i].main_info = &minfo; \
			tinfo[i].is_done = 0; \
			TEST_TRY_OR_RETURN( \
				pthread_create(&tinfo[i].thread_id, &attr, \
			                       &_test_##name##_thread, \
					       &tinfo[i]), \
				1); \
		} \
		int ret = 0; \
		for(int i = 0; i < nthreads; i++) { \
			void *res; \
			int done_thread_num; \
			TEST_TRY_OR_RETURN( \
				pthread_mutex_lock(&minfo.done_mutex), \
				1); \
			while(0 > minfo.done_thread_num) { \
				TEST_TRY_OR_RETURN( \
					pthread_cond_wait(&minfo.done_cond,  \
				                          &minfo.done_mutex), \
					1); \
			} \
			done_thread_num = minfo.done_thread_num; \
			if(0 < done_thread_num) { \
				tinfo[done_thread_num].is_done = 1; \
			} \
			minfo.done_thread_num = -1; \
			TEST_TRY_OR_RETURN( \
				pthread_mutex_unlock(&minfo.done_mutex), 1);  \
			TEST_TRY_OR_RETURN( \
				pthread_join(tinfo[done_thread_num].thread_id, \
			                     &res), \
				1); \
			/* If one thread failed the test, cancel the others.*/ \
			if(NULL != res) { \
				for(int j = 0; j < nthreads; j++) { \
					if(tinfo[j].is_done) { \
						continue; \
					} \
					/* Do not check for errors here; other \
					   threads may already be done too. */\
					pthread_cancel(tinfo[j].thread_id); \
				} \
				ret = 2; \
				break; \
			} \
		} \
		TEST_TRY_OR_RETURN(pthread_attr_destroy(&attr), 1); \
		TEST_TRY_OR_RETURN(pthread_barrier_destroy(&minfo.barrier), 1);\
		TEST_TRY_OR_RETURN(pthread_mutex_destroy(&minfo.done_mutex), \
		                   1); \
		TEST_TRY_OR_RETURN(pthread_cond_destroy(&minfo.done_cond), 1); \
		return ret; \
	} \
	static void *_test_##name##_thread(void *arg) { \
		int ret; \
		struct _test_thread_info *tinfo = arg; \
		ret = _test_##name##_thread_inner(tinfo); \
		TEST_TRY_OR_RETURN(\
			pthread_mutex_lock(&tinfo->main_info->done_mutex), \
			(void *)1L); \
		tinfo->main_info->done_thread_num = tinfo->thread_num; \
		TEST_TRY_OR_RETURN(\
			pthread_cond_signal(&tinfo->main_info->done_cond), \
			(void *)1L); \
		TEST_TRY_OR_RETURN(\
			pthread_mutex_unlock(&tinfo->main_info->done_mutex), \
			(void *)1L); \
		return (void *)(long)ret; \
	} \
	static inline int _test_##name##_thread_inner(struct _test_thread_info \
	                                              *tinfo)

#define ON_THREAD(n) if(tinfo->thread_num == n)

#define BARRIER() ({ \
	int s; \
	s = pthread_barrier_wait(&tinfo->main_info->barrier); \
	if(0 != s && PTHREAD_BARRIER_SERIAL_THREAD != s) { \
		perror("pthread_barrier_wait"); \
		return 1; \
	} \
})

#endif