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

#include "cc_private.h"

int main(int argc, char *argv[])
{
	pam_cc_handle_t *pamcch;
	char *ccredsfile;
	int rc = 0;

	if (argc > 1)
		if (strcmp(argv[1], "-h") == 0) {
			fprintf(stderr, "Usage: cc_dump [ccredsfile]\n");
			exit(rc);
		} else
			ccredsfile = argv[1];
	else
		ccredsfile = NULL;

	rc = pam_cc_start(NULL, "", ccredsfile, CC_FLAGS_READ_ONLY, &pamcch);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_cc_start failed: %s\n", pam_strerror(NULL, rc));
		exit(rc);
	}

	rc = pam_cc_dump(pamcch, stdout);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_cc_dump failed: %s\n", pam_strerror(NULL, rc));
		pam_cc_end(&pamcch);
		exit(rc);
	}

	pam_cc_end(&pamcch);

	exit(rc);
	return rc;
}


