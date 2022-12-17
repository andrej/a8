/* Included at bottom of handler_table.h. Do not use elsewhere. */

#define SYSCALL_ENUM_INIT(arch_no, name, enter, exit, arg_types, \
                          free_arg_types) \
	SYSCALL_##name##_CANONICAL,
enum syscall_canonical_no {
	SYSCALLS(SYSCALL_ENUM_INIT)
	NUM_SYSCALLS
};

#define SYSCALL_HANDLER_PROTS(_arch_no, _name, _enter, _exit, _get_arg_types, \
                              _free_arg_types) \
	SYSCALL_ENTER_PROT(_name); \
	SYSCALL_EXIT_PROT(_name); \
	SYSCALL_GET_ARG_TYPES_PROT(_name); \
	SYSCALL_FREE_ARG_TYPES_PROT(_name); \
	extern const char _name##_str[];
SYSCALLS(SYSCALL_HANDLER_PROTS)