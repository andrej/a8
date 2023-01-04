#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>

/**
 * Certain system calls never enter kernel space through a mechanism called
 * "virtual system calls." Due to this, we are unable to monitor them --
 * they bypass our system call interposition. Since the system calls are not
 * security critical (gettimeofday and time), but they will lead to divergences
 * if not replicated properly.
 * 
 * We "disable" VDSO by overwriting the C library functions that would call
 * them and instead perform a proper system call.
 */

/*
symbol                 version
─────────────────────────────────
__vdso_clock_gettime   LINUX_2.6
__vdso_getcpu          LINUX_2.6
__vdso_gettimeofday    LINUX_2.6
__vdso_time            LINUX_2.6
*/

int 
__attribute__((visibility("default")))
gettimeofday(struct timeval *restrict tv, struct timezone *restrict tz)
{

	return syscall(__NR_gettimeofday, (long)tv, (long)tz, 0, 0, 0, 0);
}
void *vdso_gettimeofday = (void *)gettimeofday;

time_t 
__attribute__((visibility("default")))
time(time_t *tloc)
{
#ifdef __NR_time

	return syscall(__NR_time, (long)tloc, 0, 0, 0, 0, 0);
#else
	struct timeval tv;
	syscall(__NR_gettimeofday, (long)&tv, 0, 0, 0, 0, 0);
	if(NULL != tloc) {
		*tloc = tv.tv_sec;
	}
	return tv.tv_sec;
#endif
}

