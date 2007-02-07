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

/* module flags */
#define SM_FLAGS_USE_FIRST_PASS		0x01
#define SM_FLAGS_TRY_FIRST_PASS		0x02
#define SM_FLAGS_GLOBAL_SESSION		0x04
#define SM_FLAGS_SERVICE_SPECIFIC	0x08

/* module actions */
#define SM_ACTION_VALIDATE_CCREDS	1
#define SM_ACTION_STORE_CCREDS		2
#define SM_ACTION_UPDATE_CCREDS		3

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
				   int flags, int argc, const char **argv);

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
			      int flags, int argc, const char **argv);

#if 0
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
				int flags, int argc, const char **argv);
#endif

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

static int _pam_sm_validate_cached_credentials(pam_handle_t *pamh,
						   int flags, unsigned int sm_flags,
						   const char *ccredsfile)
{
	int rc;
	const char *authtok;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start_ex(pamh, ((sm_flags & SM_FLAGS_SERVICE_SPECIFIC) != 0),
			     ccredsfile, CC_FLAGS_READ_ONLY, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	switch (sm_flags & (SM_FLAGS_USE_FIRST_PASS | SM_FLAGS_TRY_FIRST_PASS)) {
	case SM_FLAGS_USE_FIRST_PASS:
	case SM_FLAGS_TRY_FIRST_PASS:
		rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
		if (rc == PAM_SUCCESS) {
			if (authtok == NULL)
				authtok = "";

			rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
							 authtok, strlen(authtok));
		}
		if ((sm_flags & SM_FLAGS_USE_FIRST_PASS) || (rc == PAM_SUCCESS))
			break;
	case 0:
		rc = _pam_sm_interact(pamh, flags, &authtok);
		if (rc != PAM_SUCCESS) {
			pam_cc_end(&pamcch);
			return rc;
		}

		if (authtok == NULL)
			authtok = "";

		rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
						 authtok, strlen(authtok));
		break;
	default:
		syslog(LOG_ERR, "pam_ccreds: internal error.");
		rc = PAM_SERVICE_ERR;
	}

	if (rc == PAM_SUCCESS) {
		_pam_sm_display_message(pamh,
					"You have been logged on using cached credentials.",
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
			     ccredsfile, 0, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (rc != PAM_SUCCESS) {
		pam_cc_end(&pamcch);
		return rc;
	}

	if (authtok == NULL)
		authtok = "";

	rc = pam_cc_store_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
				      authtok, strlen(authtok));

	pam_cc_end(&pamcch);

	return rc;
}

static int _pam_sm_update_cached_credentials(pam_handle_t *pamh,
					     int flags, unsigned int sm_flags,
					     const char *ccredsfile)
{
	int rc;
	const char *authtok;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start_ex(pamh, ((sm_flags & SM_FLAGS_SERVICE_SPECIFIC) != 0),
			     ccredsfile, 0, &pamcch);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	authtok = NULL;

	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (rc != PAM_SUCCESS) {
		pam_cc_end(&pamcch);
		return rc;
	}

	if (authtok == NULL)
		authtok = "";

	rc = pam_cc_delete_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
				       authtok, strlen(authtok));

	pam_cc_end(&pamcch);

	return rc;
}

static int _pam_sm_parse_action(const char *action, unsigned int *val)
{
	if (strcmp(action, "validate") == 0)
		*val = SM_ACTION_VALIDATE_CCREDS;
	else if (strcmp(action, "store") == 0)
		*val = SM_ACTION_STORE_CCREDS;
	else if (strcmp(action, "update") == 0)
		*val = SM_ACTION_UPDATE_CCREDS;
	else
		return -1;

	return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
				   int flags, int argc, const char **argv)
{
	int i;
	int rc;
	unsigned int sm_flags = 0, sm_action = 0;
	const char *ccredsfile = NULL;
	const char *action = NULL;
	int (*selector)(pam_handle_t *, int, unsigned int, const char *);

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "use_first_pass") == 0)
			sm_flags |= SM_FLAGS_USE_FIRST_PASS;
		else if (strcmp(argv[i], "try_first_pass") == 0)
			sm_flags |= SM_FLAGS_TRY_FIRST_PASS;
		else if (strcmp(argv[i], "service_specific") == 0)
			sm_flags |= SM_FLAGS_SERVICE_SPECIFIC;
		else if (strncmp(argv[i], "ccredsfile=", sizeof("ccredsfile=") - 1) == 0)
			ccredsfile = argv[i] + sizeof("ccredsfile=") - 1;
		else if (strncmp(argv[i], "action=", sizeof("action=") - 1) == 0)
			action = argv[i] + sizeof("action=") - 1;
		else
			syslog(LOG_ERR, "pam_ccreds: illegal option %s", argv[i]);
	}

	if ((sm_flags & (SM_FLAGS_USE_FIRST_PASS | SM_FLAGS_TRY_FIRST_PASS))
	    == (SM_FLAGS_USE_FIRST_PASS | SM_FLAGS_TRY_FIRST_PASS)) {
		syslog(LOG_ERR, "pam_ccreds: both use_first_pass and try_first_pass given");
		return PAM_SERVICE_ERR;
	}

	if (action == NULL) {
		syslog(LOG_ERR, "pam_ccreds: configuration file did not "
		       "specify any action");
	} else if (_pam_sm_parse_action(action, &sm_action) != 0) {
		syslog(LOG_ERR, "pam_ccreds: invalid action \"%s\"", action);
	}

	switch (sm_action) {
	case SM_ACTION_VALIDATE_CCREDS:
		selector = _pam_sm_validate_cached_credentials;
		break;
	case SM_ACTION_STORE_CCREDS:
		selector = _pam_sm_store_cached_credentials;
		break;
	case SM_ACTION_UPDATE_CCREDS:
		selector = _pam_sm_update_cached_credentials;
		break;
	default:
		syslog(LOG_ERR, "pam_ccreds: invalid action %d", sm_action);
		return PAM_SERVICE_ERR;
	}

	rc = (*selector)(pamh, flags, sm_flags, ccredsfile);

	return rc;
}

/*
 * Although it is tempting to use the setcred interface to
 * cache the credentials, this would not be as useful as
 * it initially sounds. Why is left as an exercise to the
 * reader. :-)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
			      int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#if 0
/*
 * Presently we do not cache whether a user was allowed to
 * logon. We need to think about this, but it is difficult
 * to do reliably as logon authorization may be dependent
 * on things (time of day, for example) that one cannot
 * introspect using the PAM API. We may thus lockout a 
 * user who should otherwise be able to logon. Suggest that
 * this be configured as a matter of policy (i.e. in
 * pam.conf)
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
				int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
#endif

