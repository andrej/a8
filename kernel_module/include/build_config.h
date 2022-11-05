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

#endif