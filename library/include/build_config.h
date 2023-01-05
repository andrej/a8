#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/**
 * VERBOSITY
 * 0: Nothing at all is printed
 * 1: Errors/warnings are printed
 * 2: Basic information about system call entry/exits is logged
 * 3: Additional information for each system call is logged:
 *    - Arguments and referenced buffers
 *    - Replication of results
 *    - Adding/removing of descriptor mappings
 */
#define VERBOSITY 3

/**
 * CHECK_HASHES_ONLY
 * If true (1), the cross-check buffers are hashed and compared. 
 * If false (0), the complete serialized buffers are transmitted and compared. 
 */
#define CHECK_HASHES_ONLY 1

#define MONMOD_SYSFS_PATH "/sys/kernel/monmod"
#define MONMOD_SYSFS_UNTRACED_SYSCALLS_FILE "/untraced_syscalls"
#define MONMOD_SYSFS_TRACEE_PIDS_FILE "/tracee_pids_add"
#define MONMOD_SYSFS_TRUSTED_ADDR_FILE "/%d/trusted_addr"
#define MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE "/%d/trace_func_addr"
#define MONMOD_SYSFS_ACTIVE_FILE "/active"
#define MONMOD_LOG_FILE "./monmod%d.log"

#endif
