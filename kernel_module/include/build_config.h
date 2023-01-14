#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/**
 * If defined, skip checks for NULL pointers and certain other sanity checks
 * in hot code. If we call our functions correctly everywhere, this should not
 * break anything.
 */
#define MONMOD_SKIP_SANITY_CHECKS 0

/**
 * If defined, will print info/debug messages to kernel logs. Otherwise, only
 * errors are printed.
 */
#define MONMOD_LOG_INFO 1

/**
 * For benchmarking, memory protection calls for the monitor can be disabled.
 * This makes the system insecure, since the tracee application can write to
 * the monitor address range and hence compromise the monitor.
 */
#define MONMOD_SKIP_MONITOR_PROTECTION_CALLS 1

#endif
