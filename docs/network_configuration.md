# Network Configuration

For better performance, we connect two machines directly through an InfiniBand 
connection.  We have the following setup:

<username>PC2 (<redacted2>): **Mellanox ConnectX-5** card with 
`mlx5_core` driver in kernel.

<redacted> (ARM server): Network card on **Cavium ThunderX** motherboard, using 
`thunder-nic` driver in kernel. The double-width slot that is connected to the 
Infini-Band is the `enP2p1s0f5` interface. The Mellanox ConntectX-5 card that is 
the fastest and is the currently connected one is the `enP5p144s0` interface.

Ensure the appropriate drivers are loaded using `lspci`, which for the Mellanox
cards is `mlx5_core`.

Check that the interfaces are up and list them using `ip link`.

## Current Setup

<redacted2> and <redacted> are connected. <redacted2> is on 10.0.0.30 and <redacted> is on
10.0.0.15.

## Setting up Mellanox driver on ARM server

Mellanox/Nvidia does not provide a precompiled binary for the old Ubuntu 16.04 
we are running on the ARM server. With a simple patch it is easy to compile it 
for that operating system/ISA combination though.

0. Download sources from 
   [here](https://www.mellanox.com/products/ethernet-drivers/linux/mlnx_en).
   Choose 5.4-3.1.0, Ubuntu, Ubuntu 18.04 (the oldest version for wich ARM 
   binaries are availalbe), then **choose SOURCES**.
1. Patch the mlx5_core driver so it compiles with the missing macro.
   a. Untar `mlnx-ofed-kernel_5.4.orig.tar.gz`.
   b. Open file `MLNX_OFED_SRC-5.4-3.0.3.0/SOURCES/mlnx-ofed-kernel-5.4/drivers/infiniband/hw/mlx5/main.c`.
   c. Comment out occurences of macro `ARM_CPU_IMP_BRCM`, which seems to be 
      undefined in this Ubuntu version. There is one occurence around line 2201; 
      the driver seems to work fine with that line removed.
   d. With these changes, retar/zip the mlnx-ofed-kernel_5.4.orig` sources.
2. Run install script with `./install.pl --with-vma`. Note that this will take a
   while since it will compile all the sources and install dynamically loaded 
   kernel modukes (dkms) for the driver. Further note that you cannot run this 
   over a `nohup` SSH session, since the man page installer checks for proper 
   `stdin` / `stdout`.  That means that you will have to keep an open SSH 
   console for the duration of installation.
3. Reboot or `modprobe` the driver. For me, only rebooting completely worked to 
   support libVMA.

## Static IP Assignment

Decide on subnet to use for Mellanox card. We use the `10.0.0.0/24` subnet. 

0. Set interfaces up

       # On <redacted>:
       # sudo ip link set enP5p144s0 up
       # On <redacted2> / <redacted3>:
       # sudo ip link set enp1s0 up

1. Set interface IPs:
   
       # On <redacted>:
       sudo ip addr add 10.0.0.15/32 dev enP5p144s0
       # On <redacted2> / <redacted3>:
       sudo ip addr add 10.0.0.10/32 dev enp1s0

2. Add route to other machines to the routing tables:

       # On <redacted>:
       sudo ip route add 10.0.0.0/24 dev enP5p144s0
       # On <redacted2> / <redacted3>:
       sudo ip route add 10.0.0.0/24 dev enp1s0

Follow the instructions in `docs/vma.md` on how to use the libVMA accelerator
library together with this interface.
