# Monmod: Monitor Module

Monmod enables distributed multi-variant execution through a kernel module and a preloadable shared library.

The kernel module forwards all untrusted system calls to the shared library, which resides in a protected memory region. On each host running a program variant, the shared library maintains connections to other variants, and cross-checks that the same system calls are executed across all of them. Upon a divergence, it aborts execution.

## Installation

The following dependency is required:
- libconfig

The script `bootstrap.sh` will install it, but you still need to add `dependencies/libconfig-install/lib` to your `LD_LIBRARY_PATH` upon execution. Alternatively, you can install the `libconfig-dev` package on Ubuntu.

Build the kernel module and the library:

	cd kernel_module
	make
	cd ../library
	make
	cd ../vsyscall_override
	make

The built kernel module will be in `kernel_module/build/monmod.ko` if successful, and the shared library will be in `library/build/libmonmod.so`.

## Usage

### Prerequisite 

A configuration file is used to describe which hosts will participate in the multi variant exectuion. It looks something like this (see `experiments/configs/*.ini`):

	leader_id = 1;
	variants = (
		{
			id = 1;
			address = "10.0.0.15";
			port = 7772;
		},
		{
			id = 2;
			address = "10.0.0.30";
			port = 7772;
		}
	);

The IDs can be arbitrarily chosen and must be unique. On each host, that host's own ID must be supplied when exeucting the program using the `MONMOD_ID` environment variable.

### Running

1. Load the kernel module 
   
   ```
   sudo insmod kernel_module/build/monmod.ko
   ```

   Verify it is loaded by checking for a "monmod: module loaded" message in `/var/log/syslog`.

2. Reset the kernel module

   ```
   sudo scripts/reset_monmod.sh
   ```

   This sets some configuration parameters that the kernel module makes available in `/sys/kernel/monmod` and activates the module.

   Note: Resetting the module is recommended after each traced program. There is a maximum number of PIDs that can be monitored, and monmod will reject further requests if that number is exceeded.

3. Run the target program:  
   
   ```
   ./scripts/run.sh <id> <config_file> <target program> <arg 1> <...> <arg n>
   ```

   This is a convenience wrapper that does, approximately, the following:

   ```
   LD_LIBRARY_PATH=dependencies/libconfig-install/lib \
   LD_PRELOAD=library/build/libmonmod.so:vsyscall_override/vsyscall_override.so \
   MONMOD_ID=0 \
   MONMOD_CONFIG=experiments/configs/eiger_blackforest.ini \
   <target program>
   ```

   This preloads the shared library `libmonmod.so`.  Set the `MONMOD_CONFIG` environment variable to the same configuration file on each host, and `MONMOD_ID` to a unique chosen ID on each host, as in the configuration file.

    

### Known Issues / To-Dos

 - The `sigreturn` system call cannot currently be monitored.
 - Only one variant per physical machine can currently be monitored. Supporting multiple variants on one machine will require adjustmens to the custom system call implementation in the kernel module. (A unique link between system call enter and exit needs to be established so overlapping system calls do not mess with each other's return values through the kernel module global variables.)
