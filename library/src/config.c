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
int parse_config(const char *path, struct config *dest)
{
	config_t config;
	config_setting_t *variants_config, *variant_config;
	const char *tmp_str;
	int tmp_int;
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
	for(int i = 0; i < n_variants; i++) {
		Z_TRY(variant_config = config_setting_get_elem(variants_config,
		                                               i));
		Z_TRY(config_setting_lookup_int(variant_config, "id",
		                                 &tmp_int));
		if(config_has_id(dest, i, tmp_int)) {
			WARNF("Duplicate ID %d in configuration.\n", tmp_int);
			return 1;
		}
		dest->variants[i].id = tmp_int;
		Z_TRY(config_setting_lookup_string(variant_config, 
		                                   "address",
					    &tmp_str));
		Z_TRY(config_setting_lookup_int(variant_config, "port",
		                                &tmp_int));
		sa = (struct sockaddr_in *)&dest->variants[i].addr;
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = inet_addr(tmp_str);
		sa->sin_port = tmp_int;
	}
	return 0;
}
