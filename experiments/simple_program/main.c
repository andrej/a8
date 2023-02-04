#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	char buf[32];
	for(int i = 0; i < 20; i++) {
		snprintf(buf, sizeof(buf), "%d\n", i);
		write(1, buf, strlen(buf));
	}
	return 0;
}

