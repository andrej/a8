#ifndef INIT_H
#define INIT_H

// defined in main.c
void monmod_library_init();

// defined in arch/xx/src/init.c
void __attribute__((constructor)) monmod_do_init();

#endif