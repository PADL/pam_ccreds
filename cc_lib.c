/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <openssl/sha.h>

#include "cc_private.h"

static int _pam_cc_derive_key_ssha1(pam_cc_handle_t *pamcch,
				    pam_cc_type_t type,
				    const char *credentials,
				    size_t length,
				    char **derived_key_p,
				    size_t *derived_key_length_p)
{
	SHA_CTX sha_ctx;
	unsigned char T[4];

	T[0] = (type >> 24) & 0xFF;
	T[1] = (type >> 16) & 0xFF;
	T[2] = (type >> 8)  & 0xFF;
	T[3] = (type >> 0)  & 0xFF;

	if (SHA1_Init(&sha_ctx) != 0) {
		return PAM_SERVICE_ERR;
	}

	*derived_key_p = malloc(SHA_DIGEST_LENGTH);
	if (*derived_key_p == NULL) {
		return PAM_BUF_ERR;
	}

	*derived_key_length_p = SHA_DIGEST_LENGTH;

	/*
	 * Salt with key type, service and user names
	 */
	SHA1_Update(&sha_ctx, T, sizeof(T));
	if (pamcch->service != NULL) {
		SHA1_Update(&sha_ctx, pamcch->service, strlen(pamcch->service));
	}
	SHA1_Update(&sha_ctx, pamcch->user, strlen(pamcch->user));
	SHA1_Update(&sha_ctx, credentials, length);
	SHA1_Final(*derived_key_p, &sha_ctx);

	return PAM_SUCCESS;
}

static struct {
	pam_cc_type_t type;
	pam_cc_key_derivation_function_t function;
} _pam_cc_key_derivation_functions[] = {
	{ PAM_CC_TYPE_SSHA1, _pam_cc_derive_key_ssha1 },
	{ PAM_CC_TYPE_NONE, NULL }
};

static int _pam_cc_find_key_derivation_function(pam_cc_type_t type,
						pam_cc_key_derivation_function_t *fn_p)
{
	int i;

	for (i = 0; _pam_cc_key_derivation_functions[i].type != PAM_CC_TYPE_NONE; i++) {
		if (_pam_cc_key_derivation_functions[i].type == type) {
			*fn_p = _pam_cc_key_derivation_functions[i].function;
			return PAM_SUCCESS;
		}
	}

	return PAM_SERVICE_ERR;
}

/* Initializes a cached credentials handle */
int pam_cc_start(const char *service,
		 const char *user,
		 const struct pam_conv *conv,
		 const char *ccredsfile,
		 pam_cc_handle_t **pamcch_p)
{
	pam_cc_handle_t *pamcch;
	int rc;

	*pamcch_p = NULL;

	pamcch = (pam_cc_handle_t *)calloc(1, sizeof(*pamcch));
	if (pamcch == NULL) {
		return PAM_BUF_ERR;
	}

	if (service != NULL) {
		pamcch->service = strdup(service);
		if (pamcch->service == NULL) {
			pam_cc_end(&pamcch);
			return PAM_BUF_ERR;
		}
	} else {
		pamcch->service = NULL;
	}

	pamcch->user = strdup(user);
	if (pamcch->user == NULL) {
		pam_cc_end(&pamcch);
		return PAM_BUF_ERR;
	}

	pamcch->conv = conv;

	if (ccredsfile == NULL) {
		ccredsfile = CCREDS_FILE;
	}

	pamcch->ccredsfile = strdup(ccredsfile);
	if (pamcch->ccredsfile == NULL) {
		pam_cc_end(&pamcch);
		return PAM_BUF_ERR;
	}

	/* Initialize DB handle */
	rc = pam_cc_db_open(pamcch->ccredsfile, CC_DB_FLAGS_WRITE,
		CC_DB_MODE, &pamcch->db);
	if (rc != PAM_SUCCESS) {
		pam_cc_end(&pamcch);
		return rc;
	}

	return PAM_SUCCESS;
}

/* Initializes a cached credentials handle from PAM handle */
int pam_cc_start_ex(pam_handle_t *pamh,
		    int service_specific,
		    const char *ccredsfile,
		    pam_cc_handle_t **pamcch_p)
{
	int rc;
	const void *service;
	const void *user;
	const void *conv;

	if (service_specific) {
		rc = pam_get_item(pamh, PAM_SERVICE, &service);
		if (rc != PAM_SUCCESS) {
			return rc;
		}
	} else {
		service = NULL;
	}

	rc = pam_get_item(pamh, PAM_USER, &user);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_get_item(pamh, PAM_CONV, &conv);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_cc_start((const char *)service,
		(const char *)user,
		(struct pam_conv *)conv,
		ccredsfile,
		pamcch_p);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	return PAM_SUCCESS;
}

static int _pam_cc_encode_key(pam_cc_handle_t *pamcch,
			      pam_cc_type_t type,
			      char **key_p,
			      size_t *keylength_p)
{
	size_t keylength;
	char *key;
	size_t service_len;
	size_t user_len; 
	size_t type_buf_len;
	char type_buf[32];
	char *p;

	snprintf(type_buf, sizeof(type_buf), "%u", type);
	type_buf_len = strlen(type_buf);

	if (pamcch->service != NULL) {
		service_len = strlen(pamcch->service);
	} else {
		service_len = 0;
	}

	user_len = strlen(pamcch->user);

	/* type\0user\0[service\0] */

	keylength = type_buf_len + 1 + user_len + 1 + service_len + 1;
	key = malloc(keylength);
	if (key == NULL) {
		return PAM_BUF_ERR;
	}

	p = key;

	memcpy(p, type_buf, type_buf_len);
	p += type_buf_len;
	*p++ = '\0';

	memcpy(p, pamcch->user, user_len);
	p += user_len;
	*p++ = '\0';

	if (pamcch->service != NULL) {
		memcpy(p, pamcch->service, service_len);
		p += service_len;
	}
	*p++ = '\0';

	*key_p = key;
	*keylength_p = keylength;

	return PAM_SUCCESS;
}

/* Store credentials */
int pam_cc_store_credentials(pam_cc_handle_t *pamcch,
			     pam_cc_type_t type,
			     const char *credentials,
			     size_t length)
{
	char *key;
	size_t keylength;
	char *data;
	size_t datalength;
	int rc;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, type, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = _pam_cc_find_key_derivation_function(type, &key_derivation_fn);
	if (rc != PAM_SUCCESS) {
		free(key);
		return rc;
	}

	rc = (*key_derivation_fn)(pamcch, type, credentials, length, &data, &datalength);
	if (rc != PAM_SUCCESS) {
		free(key);
		return rc;
	}

	rc = pam_cc_db_put(pamcch->db, key, keylength, data, datalength);

	free(key);

	memset(data, 0, datalength);
	free(data);

	return rc;
}

/* Destroy credentials */
int pam_cc_destroy_credentials(pam_cc_handle_t *pamcch,
			       pam_cc_type_t type)
{
	char *key;
	size_t keylength;
	int rc;

	rc = _pam_cc_encode_key(pamcch, type, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_cc_db_delete(pamcch->db, key, keylength);

	free(key);

	return rc;
}

/* Validate credentials */
int pam_cc_validate_credentials(pam_cc_handle_t *pamcch,
				pam_cc_type_t type,
				const char *credentials,
				size_t length)
{
	char *key = NULL;
	size_t keylength;
	char *data = NULL;
	char *data_stored = NULL;
	size_t datalength, datalength_stored;
	int rc;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, type, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = _pam_cc_find_key_derivation_function(type, &key_derivation_fn);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = (*key_derivation_fn)(pamcch, type, credentials, length, &data, &datalength);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	datalength_stored = datalength;
	data_stored = malloc(datalength_stored);
	if (data_stored == NULL) {
		rc = PAM_BUF_ERR;
		goto out;
	}

	rc = pam_cc_db_get(pamcch->db, key, keylength, data_stored, &datalength_stored);
	if (rc != PAM_SUCCESS || datalength_stored != datalength) {
		rc = PAM_USER_UNKNOWN;
		goto out;
	}

	rc = PAM_AUTH_ERR;

	if (memcmp(data, data_stored, datalength) == 0) {
		rc = PAM_SUCCESS;
	}

out:
	if (key != NULL)
		free(key);

	if (data != NULL) {
		memset(data, 0, datalength);
		free(data);
	}

	if (data_stored != NULL) {
		memset(data_stored, 0, datalength_stored);
		free(data_stored);
	}

	return rc;
}

/* Destroys a cached credentials handle */
int pam_cc_end(pam_cc_handle_t **pamcch_p)
{
	pam_cc_handle_t *pamcch;
	int rc = PAM_SUCCESS;

	pamcch = *pamcch_p;
	if (pamcch != NULL) {
		if (pamcch->user != NULL) {
			free(pamcch->user);
		}

		if (pamcch->service != NULL) {
			free(pamcch->service);
		}

		if (pamcch->ccredsfile != NULL) {
			free(pamcch->ccredsfile);
		}

		if (pamcch->db != NULL) {
			rc = pam_cc_db_close(&pamcch->db);
		}

		*pamcch_p = NULL;
	}

	return rc;
}

static void _pam_cc_cleanup_data(pam_handle_t *pamh, void *data, int error)
{
	pam_cc_handle_t *pamcch = (pam_cc_handle_t *)data;

	pam_cc_end(&pamcch);
}

/* Associate a CC handle with a PAM handle */
int pam_cc_associate(pam_cc_handle_t *pamcch, pam_handle_t *pamh)
{
	return pam_set_data(pamh, PADL_CC_HANDLE_DATA,
			    (void *)pamcch, _pam_cc_cleanup_data);
}
                                                                                           
/* Deassociate a CC handle from a PAM handle */
int pam_cc_unassociate(pam_cc_handle_t *pamcch, pam_handle_t *pamh)
{
	return pam_set_data(pamh, PADL_CC_HANDLE_DATA,
			    NULL, _pam_cc_cleanup_data);
}

