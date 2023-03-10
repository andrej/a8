#!/bin/sh

ARCH=$(uname -m)
echo 0 > /sys/kernel/monmod/active
echo 1 > /sys/kernel/monmod/active

# Make the following system calls untraced:
# - brk
# - sigreturn
# - rt_sigreturn
# - mprotect (for breakpointing)
# - nanosleep
# - futex  (arm64: 98, x86_64: 202)
# - kill
# - rt_sigsuspend
# Some of these are issued by unprotected code in the breakpointing routine;
# monitoring as we are creating a checkpoint can cause issues

if [ $ARCH = "x86_64" ]
then
	echo "
12
15
10
35
130
202
" > /sys/kernel/monmod/untraced_syscalls
else
	echo "
214
139
101
226
129
133
98
" > /sys/kernel/monmod/untraced_syscalls
fi
