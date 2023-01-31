#!/bin/sh

ARCH=$(uname -m)
echo 0 > /sys/kernel/monmod/active
echo "" > /sys/kernel/monmod/tracee_pids
echo 1 > /sys/kernel/monmod/active

# Make brk and sigreturn/rt_sigreturn an untraced syscall
# also mprotect for breakpointing
# sys_nanosleep too
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
" > /sys/kernel/monmod/untraced_syscalls
fi
