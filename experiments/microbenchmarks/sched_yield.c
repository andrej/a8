#include <sched.h>
#include "build_config.h"

int main(int argc, char **argv)
{
	for(long i = 0; i < ITERATIONS; i++) {
		if(0 != sched_yield()) {
			return 1;
		}
	}
	return 0;
}