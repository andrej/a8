#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char **argv)
{
	time_t t;
	char buf[32];
	for(int i = 0; i < 20; i++) {
		t = time(NULL);
		snprintf(buf, sizeof(buf), "%d: %ld\n", i, t);
		write(1, buf, strlen(buf));
	}
	return 0;
}

