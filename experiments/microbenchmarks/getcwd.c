#include <unistd.h>
#include "build_config.h"

char buf[128];

int main(int argc, char **argv)
{
	for(long i = 0; i < ITERATIONS; i++) {
		if(buf != getcwd(buf, sizeof(buf))) {
			return 1;
		}
	}
	return 0;
}