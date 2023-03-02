# Monmod: Monitor Module

Monmod enables distributed multi-variant execution through a kernel module and a preloadable shared library.

The kernel module forwards all untrusted system calls to the shared library, which resides in a protected memory region. On each host running a program variant, the shared library maintains connections to other variants, and cross-checks that the same system calls are executed across all of them. Upon a divergence, it aborts execution.

## Installation / Building

The following dependencies are required:
- libconfig
- criu

The script `bootstrap.sh` will install those:

```
./bootstrap.sh
```

Once you are ready to run, you will need to add 
`dependencies/libconfig-install/lib` and `dependencies/criu-install/lib` to your `LD_LIBRARY_PATH` upon execution. For your convenience, using `scripts/run.sh` 
will do so for you.

Alternatively, you can install the `libconfig-dev` and `criu` packages on 
Ubuntu.

> **Note:** Before building, you can alter several settings in 
`library/include/build_config.h` and `kernel_module/include/build_config.h`.
Setting `VERBOSITY` to a high value is useful for debugging. A low value
improves performance (if nothing is logged, performance can be improved
dramatically).

To build the kernel module and the library in debug mode:

```
cd kernel_module
make
cd ../library
make
```

To build optimized (-O3 and -flto) builds:

```
cd kernel_module
opt=1 make
cd ../library
opt=1 make
```

The built kernel module will be in `kernel_module/build/monmod.ko` if successful, and the shared library will be in `library/build/libmonmod.so`.

## Usage

### Prerequisite 

A configuration file is used to describe which hosts will participate in the multi variant exectuion. Some example configuration files (for our benchmarks) are already
present in `experiments/configs/`.

It looks something like this (see `experiments/configs/*.ini`):

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

> **Note:** The configuration structures in `library/include/config.h` are 
documented thoroughly and describe all available configuration options in detail 
in the comments.

The IDs can be arbitrarily chosen and must be unique. On each host, that host's 
own ID must be supplied when exeucting the program using the `MONMOD_ID` 
environment variable. The `scripts/run.sh` wrapper will do this for you.

### Running

To run a program, you must do the following on each machine that participates in 
the multi-variant execution (each machine listed in the configuration file). 

> **Note 1:** Connections between machines are established with the lower-ID
node awaiting incoming connections, and the higher-ID attemping a new 
connection.  For example, if you have a machine with ID 1 and
a machine with ID 2, the following steps must be executed in machine 1 first,
followed by machine 2.

> **Note 2:** Each machine must have identical configuration files. Otherwise
you will run into trouble. A simple way to make sure everyone is using the
same configuration file is by copying them between the machines using `rsync`.

> **Note 3:** The executed target program, current working directory, user name,
etc., must all be the same between the running variants. Otherwise you will
get 'false positive' divergences -- for example, when opening a file in the
current working directory, the cross-checking of the `open()` call will fail
because the paths are different if the working directory is not the same in
all variants.

1. Load the kernel module 
   
   ```
   sudo insmod kernel_module/build/monmod.ko
   ```

   Verify it is loaded by checking for a "monmod: module loaded" message in 
   `/var/log/syslog`.


2. Run the target program:  
   
   ```
   ./scripts/run.sh <id> <config_file> <target program> <arg 1> <...> <arg n>
   ```

   > **Note:** This is a convenience wrapper that will load the monmod shared library
   `libmonmod.so`, set two environment variables it needs (`MONMOD_ID` and
   `MONMOD_CONFIG`) and then execute the target program normally.  It also 
   resets the kernel module and adds the `dependency` subfolders to the 
   `LD_LIBRARY_PATH`.  This is basically equivalent to:
   >
   > ```
   > LD_LIBRARY_PATH="<path to libconfig dependency>:<path to criu dependency>"
   > LD_PRELOAD="<path to library/build/libmonmod.so>"
   > MONMOD_ID=<id you gave> MONMOD_CONFIG=<config you gave>
   > <target program>
   > ```

As the program runs, if the monitor is compiled with a positive `VERBOSITY`
value, the library will log useful information to `monmod0.log`, `monmod1.log` ...,
(the number is the ID of the machine in the configuration file).

If the kernel module was compiled with a positive `VERBOSITY` value, it will 
print its logging information to `/var/log/syslog`. (May require root 
privileges to read.)

### Resetting the kernel module
    
You can reset the kernel module as follows: 

```
sudo scripts/reset_monmod.sh
```

This sets some configuration parameters that the kernel module makes available in `/sys/kernel/monmod` and activates the module.

> **Note:** Resetting the module is recommended after each traced program. There is a maximum number of PIDs that can be monitored, and monmod will reject further requests if that number is exceeded.

After making changes to the kernel module and rebuilding it, it must of course 
be reloaded to see those changes, as such

```
sudo rmmod monmod
sudo insmod kernel_module/build/monmod.ko
```
   

### Benchmarking

There are microbenchmarks for three system calls from previous work in
`experiments/microbenchmarks`. To time their native speed, use
the `time` command. For benchmarking it with our system, use one of the
`experiments/configs`.

For benchmarking `lighttpd1.4`, first, clone and build Alex's version of
lighttpd, found [here](https://github.com/balexios/lighttpd1.4), and the
`wrk` client tool, found [here](https://github.com/balexios/wrk). In the
following, we assume you cloned, followed the build instructions, and
installed in `/path/to/alex_lighttpd` and `/path/to/alex_wrk`. Then,
you will need to adjust the path to your path of `monmod` installation in
`experiments/lighttpd_config/basic_lighttpd_static_4KB.conf`. Replace
`/path/to/monmod` with the directory in which you cloned and built monmod.

Then you should be ready to run. For a native baseline (no monitoring):

```
/path/to/alex_lighttpd/sbin/lighttpd -D -f /path/to/monmod/experiments/lighttpd_config/basic_lighttpd_static_4KB.conf
```
   
The sever will run until you terminate it with CTRL-C. From another machine,
run the benchmarking client to get some numbers:

```
/path/to/alex_wrk/wrk -c10 -t1 -d10s http://<IP where you started server>:3000/index.html
```

The `-c` flag determines the number of connections for the benchmark, `-t` the
number of concurrent threads, and `-d` the duration.

Then, with a native baseline, you can compare it to an execution in the multi-
variant execution environment. Adjust the settings as necessary for your
benchmark in `experiments/configs/eiger_blackforest_lighttpd.ini`, or one
of the other configuration files. Then, on each machine (from lower to higher
ID) run:

```
/path/to/monmod/scripts/run.sh <ID> <configuration file> /path/to/alex_lighttpd/sbin/lighttpd -D -f /path/to/monmod/experiments/lighttpd_config/basic_lighttpd_static_4KB.conf
```

For example:

```
./scripts/run.sh 0 ./experiments/configs/eiger_blackforest_lighttpd.ini ~/alex_lighttpd/install/sbin/lighttpd -D -f ./experiments/lighttpd_config/basic_lighttpd_static_4KB.conf
```

### Known Issues / To-Dos

 - The `sigreturn` system call cannot currently be monitored.
