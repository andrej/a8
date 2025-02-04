#include <stdio.h>
#include <stdlib.h>

#include "test_config.h"

#if USE_FORK
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <signal.h>
#endif

#include "test.h"

ssize_t find_test(struct test *tests, size_t n_tests, const char *name)
{
	for(size_t i = 0; i < n_tests; i++) {
		if(strcmp(tests[i].name, name) == 0) {
			return i;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	struct test *tests = &__tests_start;
	size_t n_tests = ((char *)&__tests_end - (char *)&__tests_start) 
	                 / sizeof(struct test);
	size_t n_passed = 0;
#if USE_FORK
	size_t n_crashed = 0;
#endif
	size_t test_start = 0;
	size_t test_end = n_tests;

	if(argc == 2) {
		test_start = find_test(tests, n_tests, argv[1]);
		if(-1 == test_start) {
			printf("No such test: %s\n", argv[1]);
			return 1;
		}
		test_end = test_start + 1;
	}

	n_tests = test_end - test_start;

	for(size_t i = test_start; i < test_end; i++) {
		printf("%03lu/%03lu %-30s %-30s", i - test_start + 1, n_tests, 
		       tests[i].file, tests[i].name);
		fflush(stdout);
#if USE_FORK
		pid_t child = fork();
		if(child == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			int ret = tests[i].fun();
			exit(ret);
		} 
		int status = 0;
		if(wait(&status) < 0) {
			fprintf(stderr, "wait() unsuccessful.\n");
			exit(2);
		}
		int did_pass = 0;
		if(WIFEXITED(status)) {
			if(0 == WEXITSTATUS(status)) {
				n_passed += 1;
				printf(" passed\n");
			} else {
				printf(" failed\n");
			}
		} else if(WIFSIGNALED(status)) {
			n_crashed += 1;
			printf(" %s\n", strsignal(WTERMSIG(status)));
		} else {
			printf(" ?\n");
			exit(2);
		}
#else
		if(0 == tests[i].fun()) {
			n_passed += 1;
			printf(" passed\n");
		} else {
			printf(" failed\n");
		}
#endif
	}
	if(n_passed != n_tests) {
#if USE_FORK
		printf("%3lu passed. %3lu failed. %3lu crashed.\n", n_passed, 
		       n_tests - n_passed - n_crashed, n_crashed);
#else
		printf("%3lu passed. %3lu failed.\n", n_passed, 
		       n_tests - n_passed);
#endif
		return 1;
	}
	printf("All tests passed.\n");
	return 0;
}
