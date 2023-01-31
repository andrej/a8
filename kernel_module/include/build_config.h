#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/**
 * If defined, skip checks for NULL pointers and certain other sanity checks
 * in hot code. If we call our functions correctly everywhere, this should not
 * break anything.
 */
#define MONMOD_SKIP_SANITY_CHECKS 0

/**
 * Log verbosity. Choose 0 for performance.
 * 
 * 0: Nothing but errors are logged.
 * 1: monmod-specific custom system calls and other informative strings are 
 *    logged.
 * 2: All system calls that are forwarded to the monitor are additionally also
 *    logged.
 * 3: All of the above, plus unmonitored system calls are additionally logged.
 */
#define MONMOD_LOG_VERBOSITY 1

/**
 * For benchmarking, memory protection calls for the monitor can be disabled.
 * This makes the system insecure, since the tracee application can write to
 * the monitor address range and hence compromise the monitor.
 */
#define MONMOD_SKIP_MONITOR_PROTECTION_CALLS 0

#endif
