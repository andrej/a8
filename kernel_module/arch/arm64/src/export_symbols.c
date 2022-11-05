/**
 * Some of the ptrace_* function calls that we rely on are not exported to
 * kernel modules. The somewhat hacky workaround is that we hard-code those
 * function addresses. Since these are going to change between kernel versions
 * and architectures, we are conservative and only allow compilation with a
 * kernel version we know.
 * 
 * To extend this file for more kernel versions:
 *    sudo cat /boot/System.map-$(uname -r) | grep <symbolname>
 * and put the resulting address in here.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

// TODO the version reported by the header included here (4.4.98) does not 
// seem to match the output of `uname -r`. Figure out which one is right.
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,98)
//void (* ptrace_notify)(int) = (void (*)(int)) 0xffff8000000d3a58;
unsigned long long monmod_ptrace_notify_addr = 0xffff8000000d3a58;
#else
#error "Please update this file to include non-exported symbol addresses."
#endif

