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
#define VERBOSITY 1

/**
 * CHECK_HASHES_ONLY
 * If true (1), the cross-check buffers are hashed and compared. 
 * If false (0), the complete serialized buffers are transmitted and compared. 
 */
#define CHECK_HASHES_ONLY 1

/**
 * Use libVMA for intra-monitor communication. This enables fast communication
 * with direct-memory-access without a round-trip through the kernel on
 * enabled Mellanox devices.
 */
#define USE_LIBVMA 1

/**
 * If set to true, no monitoring happens. The monitor will go ahead and execute
 * the desired system call immediately with no cross-checking or replication.
 */
#define MEASURE_TRACING_OVERHEAD 1

#define MONMOD_SYSFS_PATH "/sys/kernel/monmod"
#define MONMOD_SYSFS_UNTRACED_SYSCALLS_FILE "/untraced_syscalls"
#define MONMOD_SYSFS_TRACEE_PIDS_FILE "/tracee_pids_add"
#define MONMOD_SYSFS_TRUSTED_ADDR_FILE "/%d/trusted_addr"
#define MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE "/%d/trace_func_addr"
#define MONMOD_SYSFS_ACTIVE_FILE "/active"
#define MONMOD_LOG_FILE "./monmod%d.log"

#endif
