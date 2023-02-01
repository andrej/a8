#!/bin/sh

ARCH=$(uname -m)
echo 0 > /sys/kernel/monmod/active
echo 1 > /sys/kernel/monmod/active

# Make brk and sigreturn/rt_sigreturn an untraced syscall
# also mprotect for breakpointing
# sys_nanosleep and sys_futex too
# these are all issued by unprotected code in the breakpointing routine;
# monitoring as we are creating a checkpoint can cause issues
#also sys_kill
if [ $ARCH = "x86_64" ]
then
	echo "
12
15
56
57
58
10
35
" > /sys/kernel/monmod/untraced_syscalls
else
	echo "
214
139
220
98
101
226
129
" > /sys/kernel/monmod/untraced_syscalls
fi
