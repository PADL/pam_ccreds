/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#ifndef _PAM_CC_H_
#define _PAM_CC_H_ 1                                                                                           
/*
 * PAM Cached Credentials library
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif
                                                                                           
#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif
                                                                                           
#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

struct pam_cc_handle;

typedef struct pam_cc_handle pam_cc_handle_t;

typedef enum {
	PAM_CC_TYPE_NONE = 0,
	PAM_CC_TYPE_SSHA1 = 1
} pam_cc_type_t;

/* Initializes a cached credentials handle */
int pam_cc_start(const char *service,
		 const char *user,
		 const struct pam_conv *conv,
		 const char *ccredsfile,
		 pam_cc_handle_t **pamch);

/* Initializes a cached credentials handle from PAM handle */
int pam_cc_start_ex(pam_handle_t *pamh,
		    int unique_service,
		    const char *ccredsfile,
		    pam_cc_handle_t **pamch);

/* Store credentials */
int pam_cc_store_credentials(pam_cc_handle_t *pamch,
			     pam_cc_type_t type,
			     const char *credentials,
			     size_t length);

/* Destroy credentials */
int pam_cc_destroy_credentials(pam_cc_handle_t *pamch,
			       pam_cc_type_t type);

/* Validate credentials */
int pam_cc_validate_credentials(pam_cc_handle_t *pamch,
				pam_cc_type_t type,
				const char *credentials,
				size_t length);

/* Destroys a cached credentials handle */
int pam_cc_end(pam_cc_handle_t **pamch);

/* Associate a CC handle with a PAM handle */
int pam_cc_associate(pam_cc_handle_t *pamcch, pam_handle_t *pamh);

/* Deassociate a CC handle from a PAM handle */
int pam_cc_unassociate(pam_cc_handle_t *pamcch, pam_handle_t *pamh);

#endif /* _PAM_CC_H_ */

