/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

/*
 * Glue between CC library and PAM framework
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

#include "cc_private.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

/*
 * We need to handle the following cases:
 *
 *	- If the network is down, authenticate the user
 *	  against their cached credentials
 *
 *	- If the network is up, update the cached
 *	  credentials (if the user successfully
 *	  authenticated) or delete them (if the uesr
 *	  did not)
 *
 */

#define SM_FLAGS_USE_FIRST_PASS		0x01
#define SM_FLAGS_TRY_FIRST_PASS		0x02
#define SM_FLAGS_GLOBAL_SESSION		0x04
#define SM_FLAGS_SERVICE_SPECIFIC	0x08

static int _pam_sm_interact(pam_handle_t *pamh,
			    int flags,
			    const char **authtok)
{
	int rc;
	char *p;
	const struct pam_conv *conv;
	struct pam_message msg[1];
	const struct pam_message *pmsg;
	struct pam_response *resp;

	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = (*authtok == NULL) ? "Password" : "Cached Password";

	pmsg = &msg[0];

	resp = NULL;

	rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	if (resp == NULL) {
		return PAM_CONV_ERR;
	}

	if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
		free(resp);
		return PAM_AUTH_ERR;
	}

	p = resp[0].resp;
	resp[0].resp = NULL;

	free(resp);

	*authtok = p;

	return pam_set_item(pamh, PAM_AUTHTOK, *authtok);
}

static int _pam_sm_display_message(pam_handle_t *pamh,
				   const char *message,
				   int style,
				   int flags)
{
	int rc;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *pmsg;
	struct pam_response *resp;

	if (flags & PAM_SILENT) {
		return PAM_SUCCESS;
	}

	rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	msg.msg_style = style;
	msg.msg = (char *)message;
	resp = NULL;

	pmsg = &msg;

	rc = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);

	return rc;
}

static int _pam_sm_authenticate_cached_credentials(pam_handle_t *pamh,
						   int flags, unsigned int sm_flags,
						   const char *ccredsfile)
{
	int rc;
	const char *authtok;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start_ex(pamh, ((sm_flags & SM_FLAGS_SERVICE_SPECIFIC) != 0),
			     ccredsfile, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (rc == PAM_SUCCESS && (sm_flags & (SM_FLAGS_USE_FIRST_PASS |
					      SM_FLAGS_TRY_FIRST_PASS))) {
		rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_SSHA1,
						 authtok, strlen(authtok));
	}

	if (rc != PAM_SUCCESS && (sm_flags & SM_FLAGS_USE_FIRST_PASS) == 0) {
		rc = _pam_sm_interact(pamh, flags, &authtok);
		if (rc != PAM_SUCCESS) {
			pam_cc_end(&pamcch);
			return rc;
		}

		rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_SSHA1,
						 authtok, strlen(authtok));
	}

	if (rc == PAM_SUCCESS) {
		_pam_sm_display_message(pamh,
					"You have been logged on using cached credentials",
					PAM_TEXT_INFO, flags);
	}

	pam_cc_end(&pamcch);

	return rc;
}

static int _pam_sm_store_cached_credentials(pam_handle_t *pamh,
					    int flags, unsigned int sm_flags,
					    const char *ccredsfile)
{
	int rc;
	const char *authtok;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start_ex(pamh, ((sm_flags & SM_FLAGS_SERVICE_SPECIFIC) != 0),
			     ccredsfile, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (rc != PAM_SUCCESS) {
		pam_cc_end(&pamcch);
		return rc;
	}

	rc = pam_cc_store_credentials(pamcch, PAM_CC_TYPE_SSHA1,
				      authtok, strlen(authtok));

	pam_cc_end(&pamcch);

	return rc;
}

static int _pam_sm_delete_cached_credentials(pam_handle_t *pamh,
					     int flags, unsigned int sm_flags,
					     const char *ccredsfile)
{
	int rc;
	const char *authtok;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start_ex(pamh, ((sm_flags & SM_FLAGS_SERVICE_SPECIFIC) != 0),
			     ccredsfile, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (rc != PAM_SUCCESS) {
		pam_cc_end(&pamcch);
		return rc;
	}

	rc = pam_cc_destroy_credentials(pamcch, PAM_CC_TYPE_SSHA1);

	pam_cc_end(&pamcch);

	return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
				   int flags, int argc, const char **argv)
{
	int i;
	int rc;
	unsigned int sm_flags = 0;
	const char *ccredsfile = NULL;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "use_first_pass") == 0)
			sm_flags |= SM_FLAGS_USE_FIRST_PASS;
		else if (strcmp(argv[i], "try_first_pass") == 0)
			sm_flags |= SM_FLAGS_TRY_FIRST_PASS;
		else if (strcmp(argv[i], "service_specific") == 0)
			sm_flags |= SM_FLAGS_SERVICE_SPECIFIC;
		else if (strcmp(argv[i], "ccredsfile=") == 0)
			ccredsfile = argv[i] + sizeof("ccredsfile=") - 1;
		else
			syslog(LOG_ERR, "illegal option %s", argv[i]);
	}

	// can use PAM_INCOMPLETE to call this again?

	return rc;
}

