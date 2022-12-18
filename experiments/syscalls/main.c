#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

void print_bytes(size_t sz, const char *addr)
{
	printf("a: ");
	for(size_t i = 0; i < sz; i++) {
		printf("%hhx ", addr[i]);
	}
	printf("\n");
}

void read_test(int argc)
{
	char x[10];
	size_t n = read(0, x, sizeof(x)-1);
	x[n] = '\0';
	write(1, x, n);
	return;
}

void open_readv_fstat_write_test(int argc)
{
	int fd = open("/dev/urandom", O_RDONLY);
	long a1 = 0;
	long a2 = 2;
	short a3 = 0;
	char a4 = 3;
	struct iovec iovecs[] = {
		{.iov_base = &a1, .iov_len = sizeof(a1)},
		{.iov_base = &a3, .iov_len = sizeof(a3)}
	};
	int x = readv(fd, iovecs, sizeof(iovecs)/sizeof(iovecs[0]));
	assert(x == sizeof(a1) + sizeof(a3));
	assert(a2 == 2);
	assert(a4 == 3);
	printf("%ld %hd\n", a1, a3);
}

void access_open_mmap_test(int argc)
{
	int x = access("/etc/lsb-release", R_OK);
	int fd = open("/etc/lsb-release", O_RDONLY);
	void *buf = mmap(NULL, 32, PROT_READ, MAP_PRIVATE, fd, 0);
	write(1, buf, 32);
	close(fd);
}

void write_test(int argc)
{
	const char s1[] = "Hello!\n";
	const char s2[] = "Hi!\n";
	if(1 == argc) {
		write(1, s1, sizeof(s1));
	} else {
		write(1, s2, sizeof(s2));
	}
}

void writev_test(int argc)
{
	char s1[] = "Hello,";
	char s2[] = " World";
	char s3[] = ". Hi!\n";

	struct iovec s1_iov = {
		.iov_base = &s1,
		.iov_len = sizeof(s1)
	};

	struct iovec s2_iov = {
		.iov_base = &s2,
		.iov_len = sizeof(s2)
	};

	struct iovec s3_iov = {
		.iov_base = &s3,
		.iov_len = sizeof(s3)
	};

	if(argc == 1) {
		struct iovec iovecs[] = {
			s1_iov,
			s2_iov
		};
		writev(1, iovecs, 2);	
	} else {
		struct iovec iovecs[] = {
			s1_iov,
			s3_iov
		};
		writev(1, iovecs, 2);
	}
}

int main(int argc, char **argv)
{
	//read_test(argc);
	open_readv_fstat_write_test(argc);
	access_open_mmap_test(argc);
	writev_test(argc);
	write_test(argc);
	return 0;
}
