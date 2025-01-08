/* Copyright (C) 2019 Jeremy Thien <jeremy.thien@gmail.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <libgen.h>

void usage(const char *name)
{
	printf("%s OPTIONS\n", name);
	printf("Options:\n"
			"  -k --key KEY  The private JWK to use for signing (.json)\n"
			"  -a --alg ALG  The algorithm to use for signing\n"
			"  -c --claim KEY=VALUE  A claim to add to JWT\n"
			"  -j --json '{key1:value1}'  A json to add to JWT\n"
			);
	exit(0);
}

int main(int argc, char *argv[])
{
	char *opt_key_name = NULL;
	jwt_alg_t opt_alg = JWT_ALG_NONE;
	time_t iat = time(NULL);

	int oc = 0;
	char *optstr = "hk:a:c:j:";
	struct option opttbl[] = {
		{ "help",         no_argument,        NULL, 'h'         },
		{ "key",          required_argument,  NULL, 'k'         },
		{ "alg",          required_argument,  NULL, 'a'         },
		{ "claim",        required_argument,  NULL, 'c'         },
		{ "json",         required_argument,  NULL, 'j'         },
		{ NULL, 0, 0, 0 },
	};

	char *k = NULL, *v = NULL;
	int claims_count = 0;
	int i = 0;
	char key[BUFSIZ];
	size_t key_len = 0;
	FILE *fp_priv_key;
	int ret = 0;
	jwt_auto_t *jwt = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	jwk_item_t *item = NULL;
	jwt_value_t jval;
	struct kv {
		char *key;
		char *val;
	} opt_claims[100];
	memset(opt_claims, 0, sizeof(opt_claims));
	char* opt_json = NULL;
	JWT_CONFIG_DECLARE(config);

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'k':
			opt_key_name = optarg;
			break;

		case 'a':
			opt_alg = jwt_str_alg(optarg);
			if (opt_alg >= JWT_ALG_INVAL) {
				fprintf(stderr, "%s is not supported algorithm\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'c':
			k = strtok(optarg, "=");
			if (k) {
				v = strtok(NULL, "=");
				if (v) {
					opt_claims[claims_count].key = k;
					opt_claims[claims_count].val = v;
					claims_count++;
				}
			}
			break;
		case 'j':
			opt_json = optarg;
			break;

		case 'h':
			usage(basename(argv[0]));
			return 0;

		default: /* '?' */
			usage(basename(argv[0]));
			exit(EXIT_FAILURE);
		}
	}

	fprintf(stderr, "jwtgen: privkey %s algorithm %s\n",
			opt_key_name, jwt_alg_str(opt_alg));

	if (opt_alg > JWT_ALG_NONE) {
		fp_priv_key = fopen(opt_key_name, "r");
		if (fp_priv_key == NULL) {
			perror("Failed to open key file");
			goto finish;
		}
		key_len = fread(key, 1, sizeof(key), fp_priv_key);
		fclose(fp_priv_key);
		key[key_len] = '\0';
		fprintf(stderr, "priv key loaded %s (%zu)!\n", opt_key_name, key_len);

		/* Setup JWK Set */
		jwk_set = jwks_create(key);
		if (jwk_set == NULL || jwks_error(jwk_set)) {
			fprintf(stderr, "ERR: Could not read JWK: %s\n",
				jwks_error_msg(jwk_set));
			exit(EXIT_FAILURE);
		}
		/* Get the first key */
		item = jwks_item_get(jwk_set, 0);
		if (item->error) {
			fprintf(stderr, "ERR: Could not read JWK: %s\n",
				item->error_msg);
			exit(EXIT_FAILURE);
		}

		if (item->alg == JWT_ALG_NONE && opt_alg == JWT_ALG_NONE) {
		fprintf(stderr, "Cannot find a valid algorithm in the "
			" JWK. You need to set it with --alg\n");
			exit(EXIT_FAILURE);
		}

		if (item->alg != JWT_ALG_NONE && opt_alg != JWT_ALG_NONE &&
			item->alg != opt_alg) {
			fprintf(stderr, "Key algorithm does not match --alg argument\n");
			exit(EXIT_FAILURE);
		}
	}

	config.jw_key = item;
	config.alg = opt_alg;
	jwt = jwt_create(&config);
	if (jwt == NULL) {
		fprintf(stderr, "invalid jwt\n");
		goto finish;
	}

	ret = jwt_add_grant_int(jwt, "iat", iat);
	for (i = 0; i < claims_count; i++) {
		fprintf(stderr, "Adding claim %s with value %s\n", opt_claims[i].key, opt_claims[i].val);
		jwt_add_grant(jwt, opt_claims[i].key, opt_claims[i].val);
	}

	if (opt_json != NULL) {
		ret = jwt_add_grants_json(jwt, opt_json);
		if (ret != 0) {
			fprintf(stderr, "Input json is invalid\n");
			goto finish;
		}
	}

	jwt_set_GET_JSON(&jval, NULL);
	if (jwt_header_get(jwt, &jval) == JWT_VALUE_ERR_NONE) {
		fprintf(stderr, "HEADER: %s\n", jval.json_val);
		free(jval.json_val);
	}

	jwt_set_GET_JSON(&jval, NULL);
	if (jwt_grant_get(jwt, &jval) == JWT_VALUE_ERR_NONE) {
		fprintf(stderr, "GRANTS: %s\n", jval.json_val);
		free(jval.json_val);
	}

	fprintf(stderr, "jwt algo %s!\n", jwt_alg_str(opt_alg));

	char *out = jwt_encode_str(jwt);
	printf("%s\n", out);

	free(out);

finish:
	return 0;
}

