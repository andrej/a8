#!/bin/sh

echo 0 > /sys/kernel/monmod/active
echo "" > /sys/kernel/monmod/tracee_pids
echo "" > /sys/kernel/monmod/traced_syscalls
echo 1 > /sys/kernel/monmod/active