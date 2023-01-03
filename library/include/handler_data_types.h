#ifndef HANDLER_DATA_TYPES_H
#define HANDLER_DATA_TYPES_H

#include <sys/types.h>
#include <sys/stat.h>

#define NORMALIZED_STAT_STRUCT_SIZE 116

char *normalize_stat_struct_into(struct stat *d, char *n);

void denormalize_stat_struct_into(char *n, struct stat *d);

#define NORMALIZED_EPOLL_EVENT_SIZE 16
#define NORMALIZED_EPOLL_EVENT_DATA_OFFSET 8

size_t normalize_epoll_event_structs_into(size_t num, struct epoll_event *d, 
                                          char *n);

void denormalize_epoll_event_structs_into(size_t num, 
                                          const char *n,
                                          struct epoll_event *d);

#endif