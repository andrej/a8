#include <stdlib.h>
#include "environment.h"
#include "communication.h"
#include "config.h"

void env_init(struct environment *env, 
              struct communicator *comm,
              struct config *conf, 
              int own_id)
{
	if(NULL != comm) {
		env->comm = comm;
	}

	if(NULL != conf) {
		env->leader_id = conf->leader_id;
		env->is_leader = conf->leader_id == own_id;
	}

	env->epoll_data_infos = (struct epoll_data_infos){};

	// stdin
	env_add_descriptor(env, 0, 0, DI_OPENED_ON_LEADER);

	// stdout
	env_add_descriptor(env, 1, 1, DI_OPENED_LOCALLY);

	// stderr
	env_add_descriptor(env, 2, 2, DI_OPENED_LOCALLY);
}

struct epoll_data_info *get_epoll_data_info_for(struct environment *env,
                                                int epfd,
						int fd,
						uint32_t events)
{
	struct epoll_data_info *info = 
		(struct epoll_data_info *)env->epoll_data_infos.head;
	while(NULL != info) {
		if(info->epfd == epfd && info->fd == fd
		   && (info->data.events & events)) {
			return info;
		}
		info = info->next;
	}
	return NULL;
}

int append_epoll_data_info(struct environment *env, 
                           struct epoll_data_info info)
{
	struct epoll_data_info *to_insert = malloc(sizeof(info));
	if(NULL == to_insert) {
		return 1;
	}
	memcpy(to_insert, &info, sizeof(struct epoll_data_info));
	struct epoll_data_info *tail = env->epoll_data_infos.tail;
	if(NULL != tail) {
		to_insert->prev = tail;
		tail->next = to_insert;
	} else {
		env->epoll_data_infos.head = to_insert;
		to_insert->prev = NULL;
	}
	to_insert->next = NULL;
	env->epoll_data_infos.tail = to_insert;
	return 0;
}

int remove_epoll_data_info(struct environment *env, 
                           struct epoll_data_info *info)
{
	if(info == env->epoll_data_infos.head) {
		env->epoll_data_infos.head = info->next;
	}
	if(info == env->epoll_data_infos.tail) {
		env->epoll_data_infos.tail = info->prev;
	}
	if(NULL != info->prev) {
		info->prev->next = info->next;
	}
	if(NULL != info->next) {
		info->next->prev = info->prev;
	}
	free(info);
	return 0;
}
