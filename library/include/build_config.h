#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/**
 * VERBOSITY
 * 0: Nothing at all is printed
 * 1: Errors/warnings are printed
 * 2: Basic information about system call entry/exits is logged
 * 3: Additional events for system calls are logged
 *    - Receipt/sending of replication buffers
 *    - Policy decisions (monitored vs unmonitored)
 * 4: Detailed information for each system call is logged:
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

#define USE_LIBVMA_NO 0
#define USE_LIBVMA_LOCAL 1
#define USE_LIBVMA_SERVER 2
/**
 * Use libVMA for intra-monitor communication. This enables fast communication
 * with direct-memory-access without a round-trip through the kernel on
 * enabled Mellanox devices.
 * 
 * Note: When using USE_LIBVMA_LOCAL, disable NO_HANDLER_TERMINATES below (set
 * to zero). It appears the libVMA library causes a tgkill call that we 
 * currently have no handler for.
 */
#define USE_LIBVMA USE_LIBVMA_SERVER

#ifndef LIBVMA_PATH
#define LIBVMA_PATH "/usr/lib/libvma.so"
#endif

/**
 * This can only be set in combination with USE_LIBVMA==USE_LIBVMA_SERVER. When
 * true, writes to sockets are "fire-and-forget": They return immediately and
 * it is assumed that the data can successfully be sent. This improves 
 * performance as write calls no longer block until the sent data is 
 * acknowledged.
*/
#define USE_ASYNC_WRITE 0

/**
 * If set to true, no monitoring happens. The monitor will go ahead and execute
 * the desired system call immediately with no cross-checking or replication.
 */
#define MEASURE_TRACING_OVERHEAD 0

/**
 * If set to true, execution of the program is terminated if a system call
 * that we do not have a handler for is attempted to be executed.
 */
#define NO_HANDLER_TERMINATES 0

#define NO_CHECKPOINTING 0
#define FORK_CHECKPOINTING 1
#define CRIU_CHECKPOINTING 2

/**
 * If set to false, all checkpointing code is omitted. This disables the 
 * survivability aspect and allows benchmarking a pure MVEE implementation that
 * terminates upon divergence.
 */
#define ENABLE_CHECKPOINTING FORK_CHECKPOINTING 

/**
 * Since malloc() is non-reentrant, we cannot use it in system call handlers.
 * If this flag is enabled, a safe mmap-based alternative is enabled. Note,
 * though, that this is a lot slower than malloc() and preallocated buffers
 * should be used where possible for performance.
 */
#define ENABLE_SAFE_MALLOC 0

/**
 * This size is only used if batched replication is *not* used. This is the
 * size of the preallocated buffer used to exchange replication messages.
 */
#define PREALLOCATED_REPLICATION_SZ 32768

#define HANDLER_SCRATCH_BUFFER_SZ 32768

#define CROSS_CHECK_BUFFER_SZ 8192

#define MONMOD_SYSFS_PATH "/sys/kernel/monmod"
#define MONMOD_SYSFS_UNTRACED_SYSCALLS_FILE "/untraced_syscalls"
#define MONMOD_SYSFS_TRACEE_PIDS_FILE "/tracee_pids_add"
#define MONMOD_SYSFS_TRUSTED_ADDR_FILE "/%d/trusted_addr"
#define MONMOD_SYSFS_TRACE_FUNC_ADDR_FILE "/%d/trace_func_addr"
#define MONMOD_SYSFS_ACTIVE_FILE "/active"
#define MONMOD_LOG_FILE "./monmod_%lu_%lu.log"

/**
 * The following two define the maximum size of several fixed-size arrays in
 * monitor configurations and other aspects of the monitor. Adjusting
 * these has a large impact on the size of the struct monitor. Since this is
 * "protected state" data, keeping its size minimal has a big impact on
 * overhead.
 * 
 * Therefore: try to keep this as small as possible.
 */

// config.h
#define MAX_N_VARIANTS 2
#define MAX_N_BREAKPOINTS 1

// communication.h
#define MAX_N_PEERS MAX_N_VARIANTS-1

// environment.h
#define MAX_N_DESCRIPTOR_MAPPINGS 26
#define MAX_N_PID_MAPPINGS 4
#define MAX_N_EPOLL_DATA_INFOS 128

// vma_redirect.h
#define VMA_SERVER_SMEM_SLOTS 8
#define VMA_SERVER_SMEM_SIZE 9216
//#define VMA_SERVER_SMEM_SIZE (2<<14)

/**
 * Disable headers in all exchanged messages. By default, a one-byte header
 * indicates the message type for all sent messages, such as cross-check or
 * replication message. Some header-only messages, such as "leader expecting
 * followers to report cross check buffers" are also sent (asynchronously). 
 * This is required so that execution does not hang when one variant enters
 * a cross-check while the other enters a replication. You can disable it to
 * benchmark the impact of the headers alone.
 */
#define NO_HEADERS 0

/**
 * Set to true in order to cache replication buffer. This will store the most
 * N buffers of replication information on the leader and followers. 
 */
#define USE_REPLICATION_CACHE 0

#define N_CACHE_ENTRIES 8
#define CACHE_ENTRY_MAX_SZ 256

/**
 * If (1), use XXH32 hash function. If (0), use sdbm_hash.
 */
#define USE_XXH 0

#endif
