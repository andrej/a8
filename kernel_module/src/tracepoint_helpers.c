#include "tracepoint_helpers.h"

/* ************************************************************************** *
 * Internal Data Types and Variables                                          *
 * ************************************************************************** */
struct find_tracepoint_priv {
	struct tracepoint *result;
	const char *name_query;
};

static void _find_tracepoint_by_name_cb(struct tracepoint *tp, void *priv) {
	struct find_tracepoint_priv *args = (struct find_tracepoint_priv *)priv;
	if(NULL == args
	   || NULL != args->result 
	   || NULL == args->name_query
	   || NULL == tp->name) {
		return;
	}
	if(strcmp(args->name_query, tp->name) == 0) {
		args->result = tp;
	}
}

struct tracepoint *monmod_find_kernel_tracepoint_by_name(const char *name)
{
	struct find_tracepoint_priv args = {
		NULL,
		name
	};
	for_each_kernel_tracepoint(_find_tracepoint_by_name_cb, &args);
	return args.result;
}
