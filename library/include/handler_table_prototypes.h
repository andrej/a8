/* Included at bottom of handler_table.h. Do not use elsewhere. */

#define SYSCALL_ENUM_INIT(arch_no, name, enter, exit) \
	SYSCALL_##name##_CANONICAL,
enum syscall_canonical_no {
	SYSCALLS(SYSCALL_ENUM_INIT)
	NUM_SYSCALLS
};

#define SYSCALL_HANDLER_PROTS(_arch_no, _name, _enter, _exit) \
	SYSCALL_ENTER_PROT(_name); \
	SYSCALL_EXIT_PROT(_name); \
	extern const char _name##_str[];
SYSCALLS(SYSCALL_HANDLER_PROTS)