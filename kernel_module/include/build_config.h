#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/**
 * If defined, skip checks for NULL pointers and certain other sanity checks
 * in hot code. If we call our functions correctly everywhere, this should not
 * break anything.
 */
#define MONMOD_SKIP_SANITY_CHECKS 1

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
#ifndef MONMOD_LOG_VERBOSITY
#define MONMOD_LOG_VERBOSITY 2
#endif

/**
 * For benchmarking, memory protection calls for the monitor can be disabled.
 * This makes the system insecure, since the tracee application can write to
 * the monitor address range and hence compromise the monitor.
 */
#define MONMOD_MONITOR_UNPROTECTED       0
#define MONMOD_MONITOR_MPROTECTED        1
#define MONMOD_MONITOR_FLAG_PROTECTED    2
#define MONMOD_MONITOR_HASH_PROTECTED    4
#define MONMOD_MONITOR_COMPARE_PROTECTED 8
#define MONMOD_MONITOR_PROTECTION        (MONMOD_MONITOR_FLAG_PROTECTED \
                                          | MONMOD_MONITOR_HASH_PROTECTED) 

/**
 * Scratch space size. This space is used to pass information from the system
 * call entry to the exit handler.
 */
#define MONMOD_USE_SCRATCH 1
#define MONMOD_SCRATCH_SZ 4096  // separate pages

/**
 * If set to 1, use xxhash, otherwise use sdbm_hash.
 * FIXME: xxhash is currently *broken*; it appears it accesses memory out of
 * bounds. Activating this option *will crash* your system. Leaving here in
 * case we want to fix and potentially use this hash function in the future.
 */
#define MONMOD_USE_XXH 0

#endif
