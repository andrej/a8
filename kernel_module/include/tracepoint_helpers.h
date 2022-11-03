#ifndef TRACEPOINT_HELPERS_H
#define TRACEPOINT_HELPERS_H

#ifndef TEST_H
#include <linux/kernel.h>
#include <linux/tracepoint.h>
#endif

#include "build_config.h"

struct tracepoint *monmod_find_kernel_tracepoint_by_name(const char *name);

#endif