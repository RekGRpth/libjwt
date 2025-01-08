/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jansson.h>
#include <time.h>
#include <stdarg.h>

#include "ll.h"

#ifndef ARRAY_SIZE
#  ifdef __GNUC__
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]) + \
	__builtin_types_compatible_p(typeof(__arr), typeof(&(__arr)[0])) * 0)
#  else
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]))
#  endif
#endif

JWT_NO_EXPORT
extern struct jwt_crypto_ops *jwt_ops;

/* This can be used for jwk_set_t and jwk_item_t */
#define jwks_write_error(__obj, __fmt, __args...)		\
({								\
	snprintf(__obj->error_msg, sizeof(__obj->error_msg),	\
		 __fmt, ##__args);				\
	__obj->error = 1;					\
})

struct jwt {
	jwt_alg_t alg;

	json_t *grants;
	json_t *headers;

	const jwk_item_t *jw_key;

	int error;
	char error_msg[256];
};

struct jwt_valid {
	jwt_alg_t alg;
	time_t now;
	time_t nbf_leeway;
	time_t exp_leeway;
	int hdr;
	json_t *req_grants;
	jwt_valid_exception_t status;
};

struct jwk_set {
	ll_t head;
	int error;
	char error_msg[256];
};

/**
 * This data structure is produced by importing a JWK or JWKS into a
 * @ref jwk_set_t object. Generally, you would not change any values here
 * and only use this to probe the internal parser and possibly to
 * decide whether a key applies to certain jwt_t for verification
 * or signing.
 *
 * If the jwk_item_t.pem field is not NULL, then it contains  a nil terminated
 * string of the key. The underlying crypto algorith may or may not support
 * this. It's provided as a convenience.
 */
struct jwk_item {
	ll_t node;
	char *pem;		/**< If not NULL, contains PEM string of this key	*/
	jwt_crypto_provider_t provider;	/**< Crypto provider that owns this key		*/
	union {
		void *provider_data;	/**< Internal data used by the provider		*/
		struct {
			void *key;	/**< Used for HMAC key material			*/
			size_t len;	/**< Length of HMAC key material		*/
		} oct;
	};
	int is_private_key;	/**< Whether this is a public or private key		*/
	char curve[256];	/**< Curve name of an ``"EC"`` or ``"OKP"`` key		*/
	size_t bits;		/**< The number of bits in the key (may be 0)		*/
	int error;		/**< There was an error parsing this key (unusable)	*/
	char error_msg[256];	/**< Descriptive message for @ref jwk_item_t.error	*/
	jwk_key_type_t kty;	/**< @rfc{7517,4.1} The key type of this key		*/
	jwk_pub_key_use_t use;	/**< @rfc{7517,4.2} How this key can be used		*/
	jwk_key_op_t key_ops;	/**< @rfc{7517,4.3} Key operations supported		*/
	jwt_alg_t alg;		/**< @rfc{7517,4.4} JWA Algorithm supported		*/
	char *kid;		/**< @rfc{7517,4.5} Key ID				*/
	const char *json;	/**< The entire JSON string for this key		*/
};

/* Crypto operations */
struct jwt_crypto_ops {
	const char *name;
	jwt_crypto_provider_t provider;

	/* Signing/Verifying */
	int (*sign_sha_hmac)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_hmac)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig);
	int (*sign_sha_pem)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_pem)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig_b64);

	/* Parsing a JWK to prepare it for use */
	int jwk_implemented;
	int (*process_eddsa)(json_t *jwk, jwk_item_t *item);
	int (*process_rsa)(json_t *jwk, jwk_item_t *item);
	int (*process_ec)(json_t *jwk, jwk_item_t *item);
	void (*process_item_free)(jwk_item_t *item);
};

#ifdef HAVE_OPENSSL
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_openssl_ops;
#endif
#ifdef HAVE_GNUTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_gnutls_ops;
#endif
#ifdef HAVE_MBEDTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_mbedtls_ops;
#endif

JWT_NO_EXPORT
int ops_compat(const jwk_item_t *item, const jwt_crypto_provider_t prov);

/* Memory allocators. */
JWT_NO_EXPORT
void *jwt_malloc(size_t size);
JWT_NO_EXPORT
void __jwt_freemem(void *ptr);
JWT_NO_EXPORT
void *jwt_realloc(void *ptr, size_t size);

JWT_NO_EXPORT
jwt_t *jwt_new(void);

#define jwt_freemem(__ptr) ({		\
	if (__ptr) {			\
		__jwt_freemem(__ptr);	\
		__ptr = NULL;		\
	}				\
})

static inline void jwt_freememp(char **mem) {
	jwt_freemem(*mem);
}
#define char_auto char  __attribute__((cleanup(jwt_freememp)))

/* Helper routines to handle base64url encoding without percent padding
 * as defined in RFC-4648. */
JWT_NO_EXPORT
int jwt_base64uri_encode(char **_dst, const char *plain, int plain_len);
JWT_NO_EXPORT
void *jwt_base64uri_decode(const char *src, int *ret_len);

/* JSON stuff */
JWT_NO_EXPORT
const char *get_js_string(const json_t *js, const char *key);
JWT_NO_EXPORT
long get_js_int(const json_t *js, const char *key);
JWT_NO_EXPORT
int get_js_bool(const json_t *js, const char *key);

/* A time-safe strcmp function */
JWT_NO_EXPORT
int jwt_strcmp(const char *str1, const char *str2);

JWT_NO_EXPORT
char *jwt_strdup(const char *str);

JWT_NO_EXPORT
void jwt_scrub_key(jwt_t *jwt);

JWT_NO_EXPORT
jwt_t *jwt_verify_sig(jwt_t *jwt, const char *head, unsigned int head_len,
                   const char *sig);
JWT_NO_EXPORT
int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str,
	     unsigned int str_len);

JWT_NO_EXPORT
int __append_str(char **buf, const char *str);

#define __trace() fprintf(stderr, "%s:%d\n", __func__, __LINE__)

#endif /* JWT_PRIVATE_H */
