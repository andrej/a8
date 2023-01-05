#!/bin/sh

script_dir=$(dirname $0)
lib=${script_dir}/../library/build/libmonmod.so
vso_lib=${script_dir}/../vsyscall_override/vsyscall_override.so

id=$1
config=$2
shift 2

dbg_cmd="env"

sudo ${script_dir}/reset_monmod.sh 

if [ 1 = "$DEBUG" ];
then
	dbg_cmd="gdb --args env"
fi

${dbg_cmd} \
LD_LIBRARY_PATH=${script_dir}/../dependencies/libconfig-install/lib \
LD_PRELOAD=${LD_PRELOAD}:"${lib}":"${vso_lib}" \
MONMOD_ID=${id} MONMOD_CONFIG="${config}" $@
