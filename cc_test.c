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

#include "cc.h"

static int usage(void)
{
	fprintf(stderr, "Usage: cc_test [-validate|-store|-update] [service] [user] [password] [ccredsfile]\n");
	fprintf(stderr, "       where service may be \"any\"\n");
	fprintf(stderr, "       where password may be \"-\" to delete a user\n");

	return PAM_SYSTEM_ERR;
}

int main(int argc, char *argv[])
{
	pam_cc_handle_t *pamcch;
	int rc;
	char *user;
	char *service;
	char *password;
	char *ccredsfile;
	char *action;
	const char *function = NULL;
	unsigned int cc_flags;

	if (argc < 5 || argc > 6) {
		exit(usage());
	}

	action = argv[1];
	service = (strcasecmp(argv[2], "any") == 0) ? NULL : argv[2];
	user = argv[3];
	password = (strcasecmp(argv[4], "-") == 0) ? NULL : argv[4];
	ccredsfile = (argc > 5) ? argv[5] : NULL;

	if (strcmp(action, "-validate") == 0)
		cc_flags = CC_FLAGS_READ_ONLY;
	else
		cc_flags = 0;

	rc = pam_cc_start(service, user, ccredsfile, cc_flags, &pamcch);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_cc_start failed: %s\n", pam_strerror(NULL, rc));
		exit(rc);
	}

	if (strcmp(action, "-validate") == 0 && password) {
		rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
						 password, strlen(password));
		function = "pam_cc_validate_credentials";
	} else if (strcmp(action, "-store") == 0 && password) {
		rc = pam_cc_store_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
					      password, strlen(password));
		function = "pam_cc_store_credentials";
	} else if (strcmp(action, "-update") == 0) {
		rc = pam_cc_delete_credentials(pamcch, PAM_CC_TYPE_DEFAULT,
					       password,
					       (password == NULL) ? 0 : strlen(password));
		function = "pam_cc_delete_credentials";
	} else {
		rc = usage();
	}

	if (function != NULL) {
		fprintf(stderr, "%s: %s\n", function, pam_strerror(NULL, rc));
	}

	pam_cc_end(&pamcch);

	exit(rc);
	return rc;
}

