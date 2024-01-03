#ifndef CUSTOM_SYSCALL_API_H
#define CUSTOM_SYSCALL_API_H

#define __NR_monmod_init        328
#define __NR_monmod_reprotect   329
#define __NR_monmod_destroy     330
#define __NR_monmod_fake_fork   333

#define __NR_monmod_min __NR_monmod_init
#define __NR_monmod_max __NR_monmod_fake_fork

#ifndef __ASSEMBLER__
struct monmod_monitor_addr_ranges {
	void *overall_start;
	size_t overall_len;
	void *code_start;
	size_t code_len;
	void *protected_data_start;
	size_t protected_data_len;
};
#endif

#endif