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
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

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

	SHA1_Init(&sha_ctx);

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

#if 0
static int _pam_cc_derive_key_md4(pam_cc_handle_t *pamcch,
				  pam_cc_type_t type,
				  const char *credentials,
				  size_t length,
				  char **derived_key_p,
				  size_t *derived_key_length_p)
{
}
#endif

static struct {
	pam_cc_type_t type;
	const char *name;
	pam_cc_key_derivation_function_t function;
} _pam_cc_key_derivation_functions[] = {
	{ PAM_CC_TYPE_SSHA1, "Salted SHA1", _pam_cc_derive_key_ssha1 },
	{ PAM_CC_TYPE_NONE, NULL, NULL }
};

static const char *_pam_cc_find_key_name(pam_cc_type_t type)
{
	int i;

	for (i = 0; _pam_cc_key_derivation_functions[i].type != PAM_CC_TYPE_NONE; i++) {
		if (_pam_cc_key_derivation_functions[i].type == type) {
			return _pam_cc_key_derivation_functions[i].name;
		}
	}

	return NULL;
}

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
		 const char *ccredsfile,
		 unsigned int cc_flags,
		 pam_cc_handle_t **pamcch_p)
{
	pam_cc_handle_t *pamcch;
	int rc;
	unsigned int cc_db_flags;

	*pamcch_p = NULL;

	pamcch = (pam_cc_handle_t *)calloc(1, sizeof(*pamcch));
	if (pamcch == NULL) {
		return PAM_BUF_ERR;
	}

	pamcch->flags = cc_flags;

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

	if (ccredsfile == NULL) {
		ccredsfile = CCREDS_FILE;
	}

	pamcch->ccredsfile = strdup(ccredsfile);
	if (pamcch->ccredsfile == NULL) {
		pam_cc_end(&pamcch);
		return PAM_BUF_ERR;
	}

	if (pamcch->flags & CC_FLAGS_READ_ONLY)
		cc_db_flags = CC_DB_FLAGS_READ;
	else
		cc_db_flags = CC_DB_FLAGS_WRITE;

	/* Initialize DB handle */
	rc = pam_cc_db_open(pamcch->ccredsfile, cc_db_flags,
		CC_DB_MODE, &pamcch->db);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to open cached credentials \"%s\": %m",
		       ccredsfile);
		pam_cc_end(&pamcch);
		return rc;
	}

	*pamcch_p = pamcch;

	return PAM_SUCCESS;
}

/* Initializes a cached credentials handle from PAM handle */
int pam_cc_start_ex(pam_handle_t *pamh,
		    int service_specific,
		    const char *ccredsfile,
		    unsigned int cc_flags,
		    pam_cc_handle_t **pamcch_p)
{
	int rc;
	const void *service;
	const void *user;

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

	rc = pam_cc_start((const char *)service,
		(const char *)user,
		ccredsfile,
		cc_flags,
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
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to write cached credentials \"%s\": %m",
		       pamcch->ccredsfile);
	}

	free(key);

	memset(data, 0, datalength);
	free(data);

	return rc;
}

/* Delete credentials */
int pam_cc_delete_credentials(pam_cc_handle_t *pamcch,
			      pam_cc_type_t type,
			      const char *credentials,
			      size_t length)
{
	int rc;
	char *key;
	size_t keylength;
	char *data = NULL;
	char *data_stored = NULL;
	size_t datalength, datalength_stored;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, type, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
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

	rc = pam_cc_db_get(pamcch->db, key, keylength,
			   data_stored, &datalength_stored);

	if (rc != PAM_SUCCESS || (datalength_stored != datalength && credentials)) {
		rc = PAM_IGNORE;
		goto out;
	}

	if (memcmp(data, data_stored, datalength) == 0 || !credentials) {
		/* We need to delete them */
		rc = pam_cc_db_delete(pamcch->db, key, keylength);
		if (rc != PAM_SUCCESS && rc != PAM_AUTHINFO_UNAVAIL /* not found */) {
			syslog(LOG_WARNING, "pam_ccreds: failed to delete cached "
			       "credentials \"%s\": %m",
			       pamcch->ccredsfile);
		}
	}

out:
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

int pam_cc_validate_credentials(pam_cc_handle_t *pamcch,
				pam_cc_type_t type,
				const char *credentials,
				size_t length)
{
	int rc;
	char *key = NULL;
	size_t keylength;
	char *data = NULL;
	char *data_stored = NULL;
	size_t datalength, datalength_stored;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, type, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
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

	rc = pam_cc_db_get(pamcch->db, key, keylength,
			   data_stored, &datalength_stored);

	if (rc != PAM_SUCCESS || datalength_stored != datalength) {
		rc = PAM_USER_UNKNOWN;
		goto out;
	}

	rc = PAM_AUTH_ERR;

	if (memcmp(data, data_stored, datalength) == 0) {
		rc = PAM_SUCCESS;
	}

out:
	if (key != NULL) {
		free(key);
	}

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

		free(pamcch);

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

static const char *_pam_cc_next_token(const char *key, size_t keylength,
				      const char **tok_p)
{
	ssize_t i, left;
	int terminated = 0;
	const char *ret;

	left = keylength - (*tok_p - key);
	if (left < 0) {
		return NULL;
	}

	ret = *tok_p;

	for (i = 0; i < left; i++) {
		if ((*tok_p)[i] == '\0') {
			terminated++;
			break;
		}
	}

	*tok_p += i + 1;

	if (!terminated)
		return NULL;

	if (*ret == '\0')
		return NULL;

	return ret;
}

static int _pam_cc_print_entry(FILE *fp, const char *key, size_t keylength,
			       const char *data, size_t length)
{
	/* type\0user\0[service\0] */
	pam_cc_type_t T;
	const char *p = key;
	const char *type, *user, *service;
	char sz_key_type_buf[32];
	const char *sz_key_type;

	type = _pam_cc_next_token(key, keylength, &p);
	if (type == NULL)
		return PAM_BUF_ERR;
	T = atol(type);

	user = _pam_cc_next_token(key, keylength, &p);
	if (user == NULL)
		return PAM_BUF_ERR;

	service = _pam_cc_next_token(key, keylength, &p);
	if (service == NULL)
		service = "any";

	sz_key_type = _pam_cc_find_key_name(T);
	if (sz_key_type == NULL) {
		snprintf(sz_key_type_buf, sizeof(sz_key_type_buf),
			 "Unknown key type %d", T);
		sz_key_type = sz_key_type_buf;
	}

	fprintf(fp, "%-16s %-16s %-8s", 
		sz_key_type, user, service);

	while (length--) {
		fprintf(fp, "%02x", *data++ & 0xFF);
	}
	fprintf(fp, "\n");

	return PAM_SUCCESS;
}

/* Dump contents of DB - for debugging only */
int pam_cc_dump(pam_cc_handle_t *pamcch, FILE *fp)
{
	int rc;
	const char *key, *data;
	size_t keylength, datalength;
	void *cookie = NULL;

	fprintf(fp, "%-16s %-16s %-8s %-20s\n", 
		"Credential Type", "User", "Service", "Cached Credentials");
	fprintf(fp, "----------------------------------------------------------------------------------\n");

	rc = PAM_INCOMPLETE;

	while (rc == PAM_INCOMPLETE) {
		rc = pam_cc_db_seq(pamcch->db, &cookie,
				   &key, &keylength,
				   &data, &datalength);
		if (rc != PAM_INCOMPLETE)
			break;

		_pam_cc_print_entry(fp, key, keylength, data, datalength);
	}

	return rc;
}

int pam_cc_run_helper_binary(pam_handle_t *pamh, const char *helper,
                             const char *passwd, int service_specific)
{
	int retval, child, fds[2], rc;
	void (*sighandler)(int) = NULL;
	const void *service, *user;

	rc = pam_get_item(pamh, PAM_USER, &user);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to lookup user");
		return PAM_AUTH_ERR;
	}

	if (service_specific) {
		rc = pam_get_item(pamh, PAM_SERVICE, &service);
		if (rc != PAM_SUCCESS) {
			syslog(LOG_WARNING, "pam_ccreds: failed to lookup service");
			return PAM_AUTH_ERR;
		}
	} else
		service = NULL;

	/* create a pipe for the password */
	if (pipe(fds) != 0) {
		syslog(LOG_WARNING, "pam_ccreds: failed to create pipe");
		return PAM_AUTH_ERR;
	}

	sighandler = signal(SIGCHLD, SIG_DFL);

	/* fork */
	child = fork();
	if (child == 0) {
		static char *envp[] = { NULL };
		char *args[] = { NULL, NULL, NULL, NULL };

		/* XXX - should really tidy up PAM here too */

		/* reopen stdin as pipe */
		close(fds[1]);
		dup2(fds[0], STDIN_FILENO);

		/* exec binary helper */
		args[0] = x_strdup(helper);
		args[1] = x_strdup(user);
		if (service != NULL)
			args[2] = x_strdup(service);

		syslog(LOG_WARNING, "pam_ccreds: launching helper binary");
		execve(helper, args, envp);

		/* should not get here: exit with error */
		syslog(LOG_WARNING, "pam_ccreds: helper binary is not available");
		exit(PAM_AUTHINFO_UNAVAIL);
	} else if (child > 0) {
		if (passwd != NULL) {		/* send the password to the child */
			write(fds[1], passwd, strlen(passwd) + 1);
			passwd = NULL;
		} else {
			write(fds[1], "", 1);	/* blank password */
		}

		close(fds[0]);			/* close here to avoid possible SIGPIPE above */
		close(fds[1]);
		(void) waitpid(child, &retval, 0); /* wait for helper to complete */
		retval = (retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
	} else {
		syslog(LOG_WARNING, "pam_ccreds: fork failed");
		retval = PAM_AUTH_ERR;
	}

	if (sighandler != NULL) {
		(void) signal(SIGCHLD, sighandler); /* restore old signal handler */
	}

	return retval;
}
