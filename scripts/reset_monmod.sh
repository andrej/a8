#!/bin/sh

ARCH=$(uname -m)

# Make the following system calls untraced:
# - brk
# - sigreturn
# - rt_sigreturn
# - mprotect (for breakpointing)
# - nanosleep
# - futex  (arm64: 98, x86_64: 202)
# - kill (arm64: 129, x86_64: 62)
# - rt_sigsuspend
# - clone (arm64: 220, x86_64: -)
# - clone3 (arm64: -, x86_64: 435)
# - waitid (arm64: 95, x86_64: 247)
# - set_robust_list (arm64: 99, x86_64: )
# 
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
62
247
273
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
95
99
" > /sys/kernel/monmod/untraced_syscalls
fi
