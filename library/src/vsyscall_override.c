#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>

#define GLIBC_VERSION_GEQ(maj, min) \
       (__GLIBC__ > maj || (__GLIBC__ == maj && __GLIBC_MINOR__ >= min))

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
#if GLIBC_VERSION_GEQ(2, 31)
// glibc commit 2f2c76e made tz argument a void*
gettimeofday(struct timeval *restrict tv, void *restrict tz)
#else
gettimeofday(struct timeval *restrict tv, struct timezone *restrict tz)
#endif
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

int 
__attribute__((visibility("default")))
clock_gettime(clockid_t clockid, struct timespec *tp)
{
       return syscall(__NR_clock_gettime, (long)clockid, (long)tp, 0, 0, 0, 0);
}

/* From man(2) getpid:
       From glibc version 2.3.4 up to and including version 2.24, the
       glibc wrapper function for getpid() cached PIDs, with the goal of
       avoiding additional system calls when a process calls getpid()
       repeatedly.  Normally this caching was invisible, but its correct
       operation relied on support in the wrapper functions for fork(2),
       vfork(2), and clone(2): if an application bypassed the glibc
       wrappers for these system calls by using syscall(2), then a call
       to getpid() in the child would return the wrong value (to be
       precise: it would return the PID of the parent process).  In
       addition, there were cases where getpid() could return the wrong
       value even when invoking clone(2) via the glibc wrapper function.
       (For a discussion of one such case, see BUGS in clone(2).)
       Furthermore, the complexity of the caching code had been the
       source of a few bugs within glibc over the years.  */
pid_t 
__attribute__((visibility("default")))
getpid(void)
{
	return syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
}
