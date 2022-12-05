#include <assert.h>
#include <stdlib.h>
#include "handlers.h"

#include "handler_table.h"

struct syscall_handler const *get_handler(long no)
{
	const size_t n_handlers =
		sizeof(syscall_handlers_arch)/sizeof(syscall_handlers_arch[0]);
	no -= MIN_SYSCALL_NO;
	if(0 > no || no >= n_handlers) {
		return NULL;
	}
	return syscall_handlers_arch[no];
}

SYSCALL_ENTER_PROT(    default)
{
	assert(*buf_len > 7*sizeof(long));
	memcpy(buf + 0*sizeof(long),   no, sizeof(long)); // TODO canonical no
	memcpy(buf + 1*sizeof(long), args, 6*sizeof(long));
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(     default)
{
	return;
}

SYSCALL_ENTER_PROT(    open)
{
	//int fd = args[0];
	//add_fd(env, fd);
	return 0;
}

SYSCALL_EXIT_PROT(     open)
{
	int fd = args[0];
}

SYSCALL_ENTER_PROT(    socket)
{

}

SYSCALL_EXIT_PROT(     socket)
{

}

SYSCALL_ENTER_PROT(    read)
{
	//int fd = remap_fd(env, args[0]);
	return 0;
}

SYSCALL_EXIT_PROT(     read)
{
	return;
}


/* write
   ssize_t write(int fd, const void *buf, size_t count); */

SYSCALL_ENTER_PROT(    write)
{
	if(0 > args[2]) {
		return DISPATCH_ERROR;
	}
	size_t len = *buf_len - 2*sizeof(long);
	if((size_t)args[2] < len) {
		len = args[2];
	}
	memcpy(buf, (void *)no, sizeof(long));
	memcpy(buf + 1*sizeof(long), (void *)&args[0], sizeof(long));
	memcpy(buf + 2*sizeof(long), (void *)args[1], len);
	*buf_len = len + 2*sizeof(long);
	return DISPATCH_EVERYONE | DISPATCH_CHECKED;
}

SYSCALL_EXIT_PROT(     write)
{
	return;
}


