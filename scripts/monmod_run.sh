#!/bin/sh

script_dir=$(realpath $(dirname $0))
monmod_root=$(realpath "$script_dir/..")
lib="$monmod_root/library/build/libmonmod.so"
arch=$(uname -m)

if [ "$#" -lt 3 -o ! "$1" -eq "$1" -o ! -f "$2"  ]
then
	echo "Usage: $0 <ID> <config path> <command> ...\n"
	return 1
fi

id=$1
config=$2
shift 2

dbg_cmd="env"

sudo -S ${script_dir}/reset_monmod.sh 

# Remove any previous checkpoints stored by CRIU
if [ -d criu_images ];
then
	rm -r criu_images
fi

if [ 1 = "$DEBUG" ];
then
	dbg_cmd="gdb --args env"
fi

LD_LIBRARY_PATH="$monmod_root/dependencies/libconfig-install/lib":\
"$monmod_root/dependencies/criu-install/lib/$arch-linux-gnu":\
$LD_LIBRARY_PATH \
$dbg_cmd \
LD_PRELOAD="$lib":$LD_PRELOAD \
MONMOD_ID=$id MONMOD_CONFIG="$config" $@
