#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

void ptrace_notify(int exit_code)
{
	void (* ptrace_notify_real)(int) = \
		(void (*)(int))kallsyms_lookup_name("ptrace_notify");
	if(NULL == ptrace_notify_real) {
		printk(KERN_WARNING " monmod: unable to find ptrace_notify\n");
		return;
	}
	// if((void *)monmod_ptrace_notify_addr != (void *)ptrace_notify_real) {
	// 	printk(KERN_WARNING " monmod: ptrace_notify at unexpected "
	// 	       "address %p\n", (void *)ptrace_notify_real);
	// 	return;
	// }
	ptrace_notify_real(exit_code);
}
