#!/bin/bash

rm -f /dev/shm/vmas_smem_*
killall -9 monmod_run.sh lighttpd nginx redis-server vma-server
