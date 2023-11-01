# Linking Considerations

There are some curious things going on in this repository regarding the 
linking of `libmonmod.so` that deserve a bit more thorough explanation.

The core of the monitor core is in the shared library `libmonmod.so`. The idea
is that this shared library can be preloaded into any application in order to
turn it into a monitored application (using `LD_PRELOAD`).

## Constructor

In `libmonmod.so`, we define a constructor function using 
`__attribute__((constructor))`, named `monmod_do_init()`. This function will
be called by the dynamic linker before the `main()` of the target application
is executed, giving us a chance to set up our monitoring. The function contains
architecture-specific assembly code; its code is located in the `arch/xxx/src`
folder. 

This function does not return in a regular fashion. Instead, after all 
initialization is performed (such as registering the process as
traced via call to our kernel module), a custom system call is
issued. This system call will _protect_ the memory of `libmonmod.so` (at the
address the dynamic linker has put it into the monitored process) to prevent
it from being modified by the rest of the program. After protection, it is no
longer executable, so we cannot return out of the initialization function. 
Instead, the custom system call "returns" for us, by jumping to  a return 
address passed to it. The custom assembly is needed to extract the correct 
return address to pass to the system call.

## Unprotected code

We have a section/segment in our `libmonmod.so` called "unprotected". It 
contains code that needs to be executable/readable/writable from outside the
normal monitor path. Usually, the monitor is entered through the kernel module
whenever a monitored system call occurs. The kernel module takes care of 
changing the protection bits of the text section of `libmonmod.so` so that it
can execute when needed, but is protected from tampering when it is not supposed
to run. The "unprotected" section is the only area exempt from this; the kernel
module does not change its access flags.

## Symbol visibility

Since we may be preloaded (using `LD_PRELOAD`) into any application, we need to
make sure we only export a minimal amount of symbols necessary. We do not want
to accidentally overwrite an application's own functions. Doing so would likely
lead to that application to crash. Take, for example, a function `foo()` defined
by both the application and by us. If we export the symbol, the application will
now call into `libmonmod.so` wherever it calls `foo()`, overwriting its own
definition. This will most likely lead to a segmentation fault, since our 
monitor (`libmonmod.so`) can only be entered via the kernel module and is 
execute-protected for the rest of the time for security reasons. On the other 
hand, when we call `foo()` from within our library, we need to make sure we are
still calling our own `foo()`, not the application's. This is achieved by 
making these symbols local during link time. We do so in our own code by
setting the default visibility to hidden (`-fvisibility=hidden`) and then 
explicitly marking the functions we want to export with 
`attribute((visibility("default")))`. We can verify that we do not export
unnecessary functions by running `nm build/libmonmod.so` after linking; all
symbols with lowercase `t` are private; uppercase `T` are exported.

## Linking in libconfig -- Version Script link.version

If we linked in `libconfig`, which we use for parsing our configuration files,
the regular way (i.e. just ad `-lconfig` at the end of our linker command), we 
would add a bunch of its symbols to the exported list of symbols. Apart from
our goal of not accidentally overwriting the application's symbols (see above,
symbol visibility), this leads to an opposite problem as well: Since calls into
libconfig are _dynamically_ resolved, we may accidentally be subject to calling
into application code when we mean to call into libconfig. 

This happened with `lighttpd`: Both `libconfig` and `lighttpd` define a 
`config_init` function.  When we called into `config_init`, hoping to use 
`libconfig`, this would actually run the `lighttpd` function of the same name 
instead. The core of this issue is described well here: 
https://holtstrom.com/michael/blog/post/437/Shared-Library-Symbol-Conflicts-(on-Linux).html

The workaround: instead of linking `libconfig.so` as a shared library, we link
the object files directly. The goal is to get the calls to `config_init`
(and similarly) to be defined as relative jumps, directly into the functions
defined by the object files of libconfig -- **not** a dynamically resolved 
symbol. Simply just linking in the object files instead of the `.so` is not 
enough for that yet; the `config_init` function is by default exported as a 
public symbol in `libconfig.so`, which causes the linker to leave that symbol to 
be dynamically resolved at runtime (even if it sees the definition in the `.o` -
just like when linking in the `.so`). To avoid this, we need to make
the symbol private (local) -- that way, the linker knows the symbol cannot be 
overwritten later and we mean to definitely use the function from the `.o`. 
Setting the symbol local (not exported/hidden) would be ideally done at compile 
time (see above, symbol visibility, using `-fvisibility=hidden`), but we do not 
mess with the libconfig compilation flow. Instead, we use a linker version 
script, which allows to post-hence declare which symbols should be exported, 
and which should be public. 

## Linker Script - main.lds

The dynamic loader loads sections into segments. There is one executable
segment that will contain the .text section of our `libmonmod.so`. 

Our kernel module controls access flags at the segment level using `mprotect`. 
The monitor is protected for most of the time with no access flags (no read, no
write, no execute). However, our unprotected code needs to be able to run even 
when the monitor is not allowed to. This would be easiest to accomplish if we 
could simply add a new separate segment that the loader could load with separate 
access rights. However, the GNU linker does not seem to make that easy at all. 
It would have to be done through the PHDRS command; but using it will discard 
all the default PHDRS, and it is not documented anywhere what those are.

Apparently, mapping sections to segments happens linearly through the file
offsets. So, if we add our unprotected section at the very end of the last
section that also is in the executable segment, we can simply `mprotect`
only the first part of the segment, and leave the last section unprotected. 
That's what we do here.



