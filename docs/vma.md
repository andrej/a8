# libVMA

libVMA is an accelerator library that allows exchanging data without any mode
switches to the kernel. Instead, the network card is used directly from user
space.

libVMA requires `CAP_NET_RAW` privileges. Either run the benchmark as root, or, 
to enable non-root use of libVMA, follow the following instructions. Note that
when using `fork` checkpointing together with `libVMA` you will need to use 
these instructions because the created checkpoints will be run as non-root.

Add necessary libraries with setgid set to `/usr/lib`; `LD_PRELOAD` only works
with libraries in this path for security reasons, so we must install it into
that directory.
```
sudo cp library/build/libmonmod.so /usr/lib
sudo cp dependencies/libconfig-install/lib/libconfig.so.11 /usr/lib
sudo chmod u+s /usr/lib/libmonmod.so /usr/lib/libconfig.so.11
```
(When using CRIU, you must also add the CRIU shared library to the /usr/lib 
path this way.)

Then, add the `CAP_NET_RAW` capability to the benchmark you want to run, e.g.
```
sudo setcap cap_net_raw=eip benchmarks/lighttpd/install/sbin/lighttpd
```

(To undo the last change, i.e. remove the capability, run 
`sudo setcap -r <file>`.)