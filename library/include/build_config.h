#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

#define VERBOSITY 3
#define CHECK_HASHES_ONLY 1

#define MONMOD_SYSFS_PATH "/sys/kernel/monmod"
#define MONMOD_SYSFS_UNTRACED_SYSCALLS_FILE "/untraced_syscalls"
#define MONMOD_SYSFS_TRACEE_PIDS_FILE "/tracee_pids_add"
#define MONMOD_SYSFS_TRUSTED_ADDR_FILE "/%d/trusted_addr"
#define MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE "/%d/trace_func_addr"
#define MONMOD_SYSFS_ACTIVE_FILE "/active"
#define MONMOD_LOG_FILE "./monmod%d.log"

#endif