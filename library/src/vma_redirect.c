#include "build_config.h"

#if USE_LIBVMA

#include <unistd.h>
#include "vma_redirect.h"
#include "unprotected.h"

struct socket_fptrs s = {};

pid_t
__attribute__((visibility("default"),
               section("unprotected")))
fork(void)
{
       return unprotected_funcs.syscall(__NR_monmod_fake_fork, 0,
                                        0, 0, 0, 0, 0);
}

pid_t
__attribute__((visibility("default"),
               section("unprotected")))
vmafork(void)
{
       return s.fork();
}

#endif