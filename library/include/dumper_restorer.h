#ifndef DUMPER_RESTORER_H
#define DUMPER_RESTORER_H
#include "build_config.h"

#if ENABLE_CHECKPOINTING

#include <unistd.h>
#include "checkpointing.h"

void dumper_restorer_main(struct checkpoint_env *cenv, pid_t child);

#endif

#endif