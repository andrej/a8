/* Included at bottom of handler_table.h. Do not use elsewhere. */

#define SYSCALL_ENUM_INIT(arch_no, name, enter, exit) \
	SYSCALL_##name##_CANONICAL,
enum syscall_canonical_no {
	SYSCALLS(SYSCALL_ENUM_INIT)
	NUM_SYSCALLS
};

#define SYSCALL_HANDLER_DEFS(_arch_no, _name, _enter, _exit) \
	SYSCALL_ENTER_PROT(_name); \
	SYSCALL_EXIT_PROT(_name); \
	const char _name##_str[] = #_name; \
	const struct syscall_handler _name##_handlers = { \
		.canonical_no = SYSCALL_##_name##_CANONICAL, \
		.arch_no = _arch_no, \
		.enter = _enter, \
		.exit = _exit, \
		.name = _name##_str \
	};
SYSCALLS(SYSCALL_HANDLER_DEFS)

#define SYSCALL_HANDLERS_ARCH_ARRAY_INIT(arch_no, name, enter, exit) \
	[arch_no] = &name##_handlers,
const struct syscall_handler *syscall_handlers_arch[] = {
	SYSCALLS(SYSCALL_HANDLERS_ARCH_ARRAY_INIT)
};

#define SYSCALL_HANDLERS_CANONICAL_ARRAY_INIT(arch_no, name, enter, exit) \
	[SYSCALL_##name##_CANONICAL] = &name##_handlers,
const struct syscall_handler *syscall_handlers_canonical[] = {
	SYSCALLS(SYSCALL_HANDLERS_CANONICAL_ARRAY_INIT)
};
