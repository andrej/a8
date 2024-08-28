#!/bin/bash

script_dir=$(realpath $(dirname $0))

rm -f /dev/shm/vmas_smem_*
killall -9 monmod_run.sh lighttpd nginx redis-server vma-server

sudo -S ${script_dir}/reset_monmod.sh 
