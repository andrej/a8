#!/bin/sh

script_dir=$(dirname $0)
lib=${script_dir}/../library/build/libmonmod.so
arch=$(uname -m)

id=$1
config=$2
shift 2

dbg_cmd="env"

sudo ${script_dir}/reset_monmod.sh 

# Remove any previous checkpoints stored by CRIU
if [ -d criu_images ];
then
	rm -r criu_images
fi

if [ 1 = "$DEBUG" ];
then
	dbg_cmd="gdb --args env"
fi

LD_LIBRARY_PATH="${script_dir}/../dependencies/libconfig-install/lib:\
${script_dir}/../dependencies/criu-install/lib/${arch}-linux-gnu:\
${LD_LIBRARY_PATH}" \
${dbg_cmd} \
LD_PRELOAD="${lib}":${LD_PRELOAD} \
MONMOD_ID=${id} MONMOD_CONFIG="${config}" $@
