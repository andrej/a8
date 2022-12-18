#include "environment.h"
#include "communication.h"
#include "config.h"

void env_init(struct environment *env, 
              struct communicator *comm,
              struct config *conf, 
              int own_id)
{
	env->comm = comm;
	env->leader_id = conf->leader_id;
	env->is_leader = conf->leader_id == own_id;

	// stdin
	env_add_local_descriptor(env, 0, DI_OPENED_LOCALLY);

	// stdout
	env_add_local_descriptor(env, 1, DI_OPENED_LOCALLY);

	// stderr
	env_add_local_descriptor(env, 2, DI_OPENED_LOCALLY);
}
