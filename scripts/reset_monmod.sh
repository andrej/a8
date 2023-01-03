#!/bin/sh

ARCH=$(uname -m)
echo 0 > /sys/kernel/monmod/active
echo "" > /sys/kernel/monmod/tracee_pids
echo 1 > /sys/kernel/monmod/active

# Make brk an untraced syscall
if [ $ARCH = "x86_64" ]
then
	echo "12" > /sys/kernel/monmod/untraced_syscalls
else
	echo "214" > /sys/kernel/monmod/untraced_syscalls
fi
