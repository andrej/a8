#ifndef GLOBALS_H
#define GLOBALS_H

#include <unistd.h>
#include "communication.h"

/* These are not real functions. We just use them for their address, which is
   set by the main.lds linker script to be at the start/end, respectively,
   of the "protected state" section. 
   
   Any variable that is put inside the protected state section (using
   __attribute__((section("protected_state")))) is verified by the kernel
   module to *not* change between invocations of the monitor. */
extern char __protected_state_start;
extern char __protected_state_end;

extern int monmod_log_fd;
extern size_t monmod_page_size;

extern struct monitor monitor;

/* Defined by our linker script. */
extern char __monitor_end;


#endif