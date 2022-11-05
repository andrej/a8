#include <linux/kernel.h>
#include <linux/version.h>

// TODO the version reported by the header included here (4.4.98) does not 
// seem to match the output of `uname -r`. Figure out which one is right.
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,98)
//void (* ptrace_notify)(int) = (void (*)(int)) 0xffff8000000d3a58;
unsigned long long monmod_ptrace_notify_addr = 0xffff8000000d3a58;
#else
#error "Please update this file to include non-exported symbol addresses."
#endif

