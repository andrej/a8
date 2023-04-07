#include "policy.h"
#include "handler_table.h"

#define POLICY_ARR_DEF(X) {#X, policy_ ## X ## _is_exempt},
__attribute__((section("protected_state")))
struct policy policies[] = {
	POLICIES(POLICY_ARR_DEF)
};

#define POLICY_EXEMPT(X) bool POLICY_IS_EXEMPT_FN(X)( \
			      const struct syscall_info * const canonical, \
			      const struct environment * const env)

POLICY_EXEMPT(full)
{
	return false;
}

POLICY_EXEMPT(base)
{
	switch(canonical->no) {
		case SYSCALL_gettimeofday_CANONICAL:
		//case SYSCALL_clock_gettime_CANONICAL:
		case SYSCALL_time_CANONICAL:
		case SYSCALL_getpid_CANONICAL:
		//case SYSCALL_gettid_CANONICAL:
		//case SYSCALL_getpgrp_CANONICAL:
		case SYSCALL_getppid_CANONICAL:
		case SYSCALL_getgid_CANONICAL:
		case SYSCALL_getegid_CANONICAL:
		case SYSCALL_getuid_CANONICAL:
		case SYSCALL_geteuid_CANONICAL:
		case SYSCALL_getcwd_CANONICAL:
		//case SYSCALL_getpriority_CANONICAL:
		//case SYSCALL_getrusage_CANONICAL:
		//case SYSCALL_times_CANONICAL:
		//case SYSCALL_capget_CANONICAL:
		//case SYSCALL_getitimer_CANONICAL:
		//case SYSCALL_sysinfo_CANONICAL:
		case SYSCALL_uname_CANONICAL:
		case SYSCALL_sched_yield_CANONICAL:
		//case SYSCALL_nanosleep _CANONICAL:
			return true;
		default:
			return false;
	}
}

POLICY_EXEMPT(nonsocket_ro)
{
	switch(canonical->no) {
		case SYSCALL_access_CANONICAL:
		case SYSCALL_faccessat_CANONICAL:
		case SYSCALL_lseek_CANONICAL:
		case SYSCALL_stat_CANONICAL:
		//case SYSCALL_lstat_CANONICAL:
		case SYSCALL_fstat_CANONICAL:
		case SYSCALL_fstatat_CANONICAL:
		//case SYSCALL_getdents_CANONICAL:
		//case SYSCALL_readlink_CANONICAL:
		//case SYSCALL_readlinkat_CANONICAL:
		//case SYSCALL_getxattr_CANONICAL:
		//case SYSCALL_lgetxattr_CANONICAL:
		//case SYSCALL_fgetxattr_CANONICAL:
		//case SYSCALL_alarm_CANONICAL:
		//case SYSCALL_setitimer_CANONICAL:
		//case SYSCALL_timerfd_gettime_CANONICAL:
		//case SYSCALL_madvise_CANONICAL:
		//case SYSCALL_fadvise64_CANONICAL:
			return true;
		case SYSCALL_read_CANONICAL:
		case SYSCALL_readv_CANONICAL: 
		//case SYSCALL_pread64_CANONICAL:
		//case SYSCALL_select_CANONICAL:
		//case SYSCALL_poll_CANONICAL:
		{
			const struct descriptor_info *di;
			SAFE_NZ_TRY(
				di = env_get_canonical_descriptor_info(
						(struct environment *)env, 
						canonical->args[0]));
			if(SOCKET_DESCRIPTOR == di->type) {
				return false;
			}
			return true;

		}
		//case SYSCALL_futex_CANONICAL:
		case SYSCALL_ioctl_CANONICAL:
		case SYSCALL_fcntl_CANONICAL:
			return true;
		default:
			return policy_is_exempt_static(base, canonical, env);
	}
}

POLICY_EXEMPT(nonsocket_rw)
{
	switch(canonical->no) {
		//case SYSCALL_sync_CANONICAL:
		//case SYSCALL_syncfd_CANONICAL:
		//case SYSCALL_fsync_CANONICAL:
		//case SYSCALL_fdatasync_CANONICAL:
		//case SYSCALL_timerfd_settime_CANONICAL:
		//	return true;
		case SYSCALL_write_CANONICAL:
		case SYSCALL_writev_CANONICAL:
		//case SYSCALL_pwrite64_CANONICAL:
		//case SYSCALL_pwritev_CANONICAL:
		{
			const struct descriptor_info *di;
			SAFE_NZ_TRY(
				di = env_get_canonical_descriptor_info(
						(struct environment *)env, 
						canonical->args[0]));
			if(SOCKET_DESCRIPTOR == di->type) {
				return false;
			}
			return true;
		}
		default:
			return policy_is_exempt_static(nonsocket_ro, canonical, 
			                               env);
	}
}

POLICY_EXEMPT(socket_ro)
{
	switch(canonical->no) {
		case SYSCALL_read_CANONICAL:
		case SYSCALL_readv_CANONICAL:
		//case SYSCALL_pread64_CANONICAL:
		//case SYSCALL_preadv_CANONICAL:
		//case SYSCALL_select_CANONICAL:
		//case SYSCALL_poll_CANONICAL:
		case SYSCALL_epoll_wait_CANONICAL:
		case SYSCALL_epoll_pwait_CANONICAL:
		case SYSCALL_recvfrom_CANONICAL:
		//case SYSCALL_recvmsg_CANONICAL:
		//case SYSCALL_recvmmsg_CANONICAL:
		case SYSCALL_getsockname_CANONICAL:
		case SYSCALL_getpeername_CANONICAL:
		case SYSCALL_getsockopt_CANONICAL:
			return true;
		default:
			return policy_is_exempt_static(nonsocket_ro, canonical, 
			                               env);
	}
}

POLICY_EXEMPT(socket_rw)
{
	switch(canonical->no) {
		case SYSCALL_write_CANONICAL:
		case SYSCALL_writev_CANONICAL:
		//case SYSCALL_pwrite64_CANONICAL:
		//case SYSCALL_pwritev_CANONICAL:
		//case SYSCALL_sendto_CANONICAL:
		//case SYSCALL_sendmsg_CANONICAL:
		//case SYSCALL_sendmmsg_CANONICAL:
		case SYSCALL_sendfile_CANONICAL:
		case SYSCALL_epoll_ctl_CANONICAL:
		case SYSCALL_setsockopt_CANONICAL:
		case SYSCALL_shutdown_CANONICAL:
			return true;
		default:
			return policy_is_exempt_static(socket_ro, canonical,
			                               env);
	}
}

POLICY_EXEMPT(socket_rw_oc)
{
	switch(canonical->no) {
		case SYSCALL_open_CANONICAL:
		case SYSCALL_openat_CANONICAL:
		case SYSCALL_close_CANONICAL:
			return true;
		default:
			return policy_is_exempt_static(socket_rw, canonical,
			                               env);
	}
}

struct policy *policy_from_str(const char *str)
{
	for(struct policy *policy = &policies[0];
	    policy < policies + (sizeof(policies)/sizeof(policies[0]));
	    policy++) {
		if(0 == strcmp(policy->name, str)) {
			return policy;
		}
	}
	return NULL;
}
