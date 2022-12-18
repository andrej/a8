/* Do NOT include this file. Contains definitions for all handlers to be 
   included in handlers.c. Link against handlers.o to get these definitions.
   Use handler_table_protoypes.h as an include. */

#define SYSCALL_HANDLER_DEFS(_arch_no, _name, _enter, _exit, \
                             _get_normalized_args, _free_normalized_args) \
	const char _name##_str[] = #_name; \
	const struct syscall_handler _name##_handlers = { \
		.canonical_no = SYSCALL_##_name##_CANONICAL, \
		.arch_no = _arch_no, \
		.enter = _enter, \
		.exit = _exit, \
		.normalize_args = _get_normalized_args, \
		.free_normalized_args = _free_normalized_args, \
		.name = _name##_str \
	};
SYSCALLS(SYSCALL_HANDLER_DEFS)

#define SYSCALL_HANDLERS_ARCH_ARRAY_INIT(arch_no, name, enter, exit, \
                                         normalize_args, \
					 free_normalized_args)\
	[arch_no] = &name##_handlers,
const struct syscall_handler * const syscall_handlers_arch[] = {
	SYSCALLS(SYSCALL_HANDLERS_ARCH_ARRAY_INIT)
};

#define SYSCALL_HANDLERS_CANONICAL_ARRAY_INIT(arch_no, name, enter, exit, \
                                              normalize_args, \
					      free_normalized_args) \
	[SYSCALL_##name##_CANONICAL] = &name##_handlers,
const struct syscall_handler * const syscall_handlers_canonical[] = {
	SYSCALLS(SYSCALL_HANDLERS_CANONICAL_ARRAY_INIT)
};
