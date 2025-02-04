# A⁸: Survivable Heterogeneous Multi-Variant Execution (MVX)

A⁸ enables _survivable_ distributed, heterogeneous multi-variant execution with checkpoint-restore through a kernel module and a preloadable shared library.

A⁸ was presented at the [2024 Annual Compuer Security Applications Conference (ACSAC)](https://www.openconf.org/acsac2024/modules/request.php?module=oc_program&action=summary.php&id=73).
The artifacts used in that paper are available on the _ae2_ branches of this repository and the a8-benchmarks repository, see [here](https://github.com/andrej/a8-benchmarks/blob/ae2/artifact_eval/README.md). This is the abstract of that publication:

> Abstract—Multi-variant execution (MVX) is a low-friction approach to increase the security of critical software applications.
> MVX systems execute multiple diversified implementations of the same software in lockstep on the same inputs, while monitoring each variant’s behavior. 
> MVX systems can detect attacks quickly and with high probability, because low-level vulnerabilities are unlikely to manifest in precisely the same manner across sufficiently diversified variants. 
> Existing MVX systems terminate execution when they detect a divergence in behavior between variants.
> In this paper, we present A⁸, which we believe is the first full-scale survivable MVX system that not only detects attacks as they happen, but is also able to recover from them. 
> Our implementation is comprised of two parts, an MVX portion that leverages the natural heterogeneity of variants running on diverse platforms (ARM64 and x86 64), and a checkpoint/restore portion that periodically creates snapshots of the variants’ states and forces variants to roll back to those snapshots upon detection of any irregular behavior. 
> In this way, A⁸ achieves availability even in the face of continuous remote attacks.
> We consider several design choices and evaluate their security and performance trade-offs using microbenchmarks.
> Chiefly among these, we devise a system call interposition and monitor implementation approach that provides secure isolation of the MVX monitor, minimal kernel changes (small privileged TCB), and low overheads – a combination not before seen in the context of MVX.
> We also perform a real-world evaluation of our system on two popular web servers, lighttpd and nginx, and the database server redis, which are able to maintain 53%-71% of their throughput compared to native execution.

The kernel module forwards all untrusted system calls to the shared library, which resides in a protected memory region. On each host running a program variant, the shared library maintains connections to other variants, and cross-checks that the same system calls are executed across all of them. Upon a divergence, it aborts execution.

> Note: The working title of this project was **monmod**, which is why it pops up everywhere in the source code.
> We may rename these occurences to "a8" in the future.

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

A configuration file is used to describe which hosts will participate in the multi variant exectuion.  It looks something like this:

#### Simple Configuration (No Checkpoint/Restore)

```
leader_id = 0;
variants = (
	{
		id = 0;
		address = "10.0.0.15";
		port = 7772;
	},
	{
		id = 1;
		address = "10.0.0.30";
		port = 7772;
	}
);
```

The IDs can be arbitrarily chosen and must be unique. On each host, that host's 
own ID must be supplied when exeucting the program using the `MONMOD_ID` 
environment variable. The `scripts/run.sh` wrapper will do this for you.


> **Note:** The configuration structures in `library/include/config.h` are 
documented thoroughly and describe all available configuration options in detail 
in the comments.

<details>
<summary>

#### More complete configuration example

To enable checkpoint/restore, you will need to add brakpoints to this configuration. Where you add breakpoints depends on your target application. Here is an example of a more complete configuration:

</summary>

```
leader_id = 0;

# The policy decides which system calls are allowed to go unchecked.
policy = "socket_rw_oc";
# The replication batch size determines how many back-to-back unchecked system
# calls can proceed before all variants are synchronized.
replication_batch_size = 8192;

# The following two options can be used to simulate divergences and test the
# checkpoint restoring feature.
restore_probability = 0;
inject_fault_probability = 0;

variants = (
	{ # variant 0
		id = 0;
		address = "10.0.0.15";
		port = 7773;
		# Breakpoints indicate where checkpoints are created.
		breakpoints = (
			{
				# An interval of 1 means a checkpoint is created
				# every time this breakpoint is hit (2 would
				# mean every other time, and so on).
				interval = 1;
				# The following determines where the breakpoint
				# is created, using the address of the symbol
				# plus a fixed offset (in bytes). `instr_len`
				# *must* match the exact size of the 
				# instruction at that address (use e.g.
				# `objdump --disassemble` to determine this).
				symbol = "ngx_close_connection";
				offset = 0;
				instr_len = 4;
			}
		) 
	},
	{ # variant 1
		id = 1;
		address = "10.0.0.30";
		port = 7774;
		breakpoints = (
			{
				interval = 1;
				symbol = "ngx_close_connection";
				offset = 4;
				instr_len = 2;
			}

		) 
	}
);
```

</details>

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

2. (Optional) Add the `scripts` folder to your PATH for convenience.

   ```
   export PATH=/path/to/monmod/scripts:$PATH
   ```

3. Run the target program:  
   
   ```
   monmod_run.sh <ID> <config file> <target program> <program args ...>
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
value, the library will log useful information to `monmod_0_0.log`, `monmod_1_0.log` ...,
(the first number is the ID of the machine in the configuration file, and the second number increases as the program spawns child processes which are monitored separately).

If the kernel module was compiled with a positive `VERBOSITY` value, it will 
print its logging information to `/var/log/syslog`. (May require root 
privileges to read.)

_More examples of running A⁸ for some benchmarks are given in the [benchmarks repository](https://github.com/andrej/a8-benchmarks/)._

### Debugging

If you run into trouble, first increase the `VERBOSITY` configuration values in 
`library/include/build_config.h` and `kernel_module/include/build_config.h` to their max values (4 and 3, respectively). Re-compile as outlined above and re-run the broken example. Then, examine the log files:

- `monmod_<id>_<child_id>.log` for potential issues in the shared library
- `/var/log/syslog` (any outputs prefixed "monmod") for the kernel moduel

A likely category of bugs is for unmapped or improperly mapped system calls. We have not tested any other benchmarks except for the ones in the benchmark repository; new applications will likely exercise different system calls for which we don't have handlers yet or for which the handlers are incomplete. The configuration `NO_HANDLER_TERMINATES` in `library/include/build_config.h` should be set to `1`; this way, the program will quit as soon as it encounters a system call for which no handler exists. It may be tempting to disable this and allow the program to continue executing, but this will likely lead to problems down the line. We need handlers for all system calls to properly update our internal states (e.g. canonical file descriptor handles to "real" file descriptor handles).

For bugs in the kernel module, it can be beneificial to run `sudo tail -F /var/log/syslog` concurrently in a different terminal. That way, if the kernel crashes and the server needs to be restarted, you will have a terminal that shows the last logs written before the server crashed.

Lastly, it can be beneficial to attach a debugger to a program executing under A8. This is only possible if we do not use checkpoint/restore. When using checkpoint/restore, new processes will be constantly spawned, and the debugger will not know which child proces to follow. To attach a debugger to a program under A8 execution, use the `monmod_run.sh` script with `DEBUG=1` environment variable. This will start the target program under gdb:

```
DEBUG=1 monmod_run.sh <id> <config> ...
```

You can then set a breakpoint at the function `monmod_handle_syscall`; this will allow you to inspect every system call that A8 monitors.

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
   
### Known Issues / To-Dos

 - The `sigreturn` system call cannot currently be monitored.
