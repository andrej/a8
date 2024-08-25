#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libconfig.h>
#include "util.h"
#include "config.h"


/* ************************************************************************** *
 * Internals                                                                  *
 * ************************************************************************** */ 
static int config_has_id(struct config *conf, int i, int id)
{
	for(int j = 0; j < i; j++) {
		if(conf->variants[j].id == id) {
			return 1;
		}
	}
	return 0;
}


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */ 

/* A bug in libconfig leads to a segmentation fault with lighttpd 1.4.71 when
   the config_t is located on the stack. Put it on heap as global instead.
   Only move this variable back into parse_config() function after verifying 
   monmod still works running lighttpd 1.4.71. */
config_t config = {};

int parse_config(const char *path, struct config *dest)
{
	config_setting_t *variants_config, *variant_config, *breakpoints_config,
	                 *breakpoint_config;
	const char *tmp_str;
	int tmp_int;
	long long tmp_long;
	double tmp_float;
	struct sockaddr_in *sa;
	int n_variants;

	memset(dest, 0, sizeof(struct config));

	config_init(&config);
	config_read_file(&config, path);

	Z_TRY(config_lookup_int(&config, "leader_id", &dest->leader_id));
	Z_TRY(variants_config = config_lookup(&config, "variants"));
	Z_TRY(n_variants = config_setting_length(variants_config));
	if(n_variants > MAX_N_VARIANTS) {
		return 2;
	}
	dest->n_variants = n_variants;

	if(config_lookup_int(&config, "replication_batch_size", &tmp_int)) {
		dest->replication_batch_size = tmp_int;
	} else {
		dest->replication_batch_size = 0;
	}

	if(config_lookup_string(&config, "policy", &tmp_str)) {
		strncpy(dest->policy, tmp_str, sizeof(dest->policy));
	} else {
		strncpy(dest->policy, "full", sizeof(dest->policy));
	}

	if(config_lookup_float(&config, "restore_probability", 
	                     &tmp_float)) {
		Z_TRY(tmp_float >= 0 && tmp_float < 1);
		dest->restore_probability = tmp_float;
	}

	if(config_lookup_float(&config, "inject_fault_probability", &tmp_float))
	{
		Z_TRY(tmp_float >= 0 && tmp_float < 1);
		dest->inject_fault_probability = tmp_float;
	} else {
		dest->inject_fault_probability = 0;
	}

	if(config_lookup_int(&config, "socket_read_usleep", &tmp_int))
	{
		dest->socket_read_usleep = tmp_int;
	} else {
		dest->socket_read_usleep = 0;
	}

	for(int i = 0; i < n_variants; i++) {
		Z_TRY(variant_config = config_setting_get_elem(variants_config,
		                                               i));
		
		// variant ID
		Z_TRY(config_setting_lookup_int(variant_config, "id",
		                                 &tmp_int));
		if(config_has_id(dest, i, tmp_int)) {
			WARNF("Duplicate ID %d in configuration.\n", tmp_int);
			return 1;
		}
		dest->variants[i].id = tmp_int;

		// variant address + port
		Z_TRY(config_setting_lookup_string(variant_config, 
		                                   "address",
					    &tmp_str));
		Z_TRY(config_setting_lookup_int(variant_config, "port",
		                                &tmp_int));
		sa = (struct sockaddr_in *)&dest->variants[i].addr;
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = inet_addr(tmp_str);
		sa->sin_port = htons(tmp_int);

		// variant breakpoints
		dest->variants[i].n_breakpoints = 0;
		breakpoints_config = config_setting_lookup(variant_config, 
		                                          "breakpoints");
		if(NULL != breakpoints_config) {
			dest->variants[i].n_breakpoints = 
				config_setting_length(breakpoints_config);
			for(int j = 0; j < dest->variants[i].n_breakpoints; j++)
			{
				Z_TRY(breakpoint_config = 
				     config_setting_get_elem(breakpoints_config,
				                             j));
				bool symbol_or_offset_defined = false;
				if(config_setting_lookup_string(breakpoint_config, "symbol", 
				                                &tmp_str)) {
					strncpy(dest->variants[i].breakpoints[j].symbol, 
					        tmp_str, 
							sizeof(dest->variants[i].breakpoints[j].symbol));
					symbol_or_offset_defined = true;
				}
				if(config_setting_lookup_int64(
						breakpoint_config, "offset", &tmp_long)) {
					dest->variants[i].breakpoints[j].offset = tmp_long;
					symbol_or_offset_defined = true;
				}
				NZ_TRY(!symbol_or_offset_defined && "must define either "
				       "offset, symbol, or both for each breakpoint.");
				Z_TRY(config_setting_lookup_int64(
					breakpoint_config, "instr_len",
					&tmp_long));
				dest->variants[i].breakpoints[j].instr_len = \
					(size_t)tmp_long;
				Z_TRY(config_setting_lookup_int(
					breakpoint_config, "interval", 
					&tmp_int));
				dest->variants[i].breakpoints[j].interval = 
					tmp_int;
			}
		}

	}
	return 0;
}
