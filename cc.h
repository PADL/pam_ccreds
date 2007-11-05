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
	PAM_CC_TYPE_SSHA1 = 1,
	PAM_CC_TYPE_MD4 = 2,
	PAM_CC_TYPE_DEFAULT = PAM_CC_TYPE_SSHA1
} pam_cc_type_t;

#define CC_FLAGS_READ_ONLY	0x01

/* Initializes a cached credentials handle */
int pam_cc_start(const char *service,
		 const char *user,
		 const char *ccredsfile,
		 unsigned int cc_flags,
		 pam_cc_handle_t **pamcch);

/* Initializes a cached credentials handle from PAM handle */
int pam_cc_start_ext(pam_handle_t *pamh,
		    int unique_service,
		    const char *ccredsfile,
		    unsigned int cc_flags,
		    pam_cc_handle_t **pamcch);

/* Store credentials */
int pam_cc_store_credentials(pam_cc_handle_t *pamcch,
			     pam_cc_type_t type,
			     const char *credentials,
			     size_t length);

/* Delete credentials - if credentials supplied only on match */
int pam_cc_delete_credentials(pam_cc_handle_t *pamcch,
			      pam_cc_type_t type,
			      const char *credentials,
			      size_t length);

/* Validate credentials */
int pam_cc_validate_credentials(pam_cc_handle_t *pamcch,
				pam_cc_type_t type,
				const char *credentials,
				size_t length);

/* Destroys a cached credentials handle */
int pam_cc_end(pam_cc_handle_t **pamcch);

/* Associate a CC handle with a PAM handle */
int pam_cc_associate(pam_cc_handle_t *pamcch, pam_handle_t *pamh);

/* Deassociate a CC handle from a PAM handle */
int pam_cc_unassociate(pam_cc_handle_t *pamcch, pam_handle_t *pamh);

/* Dump contents - for debugging only */
int pam_cc_dump(pam_cc_handle_t *pamcch, FILE *fp);

/* Execute ccreds_* */
int pam_cc_run_helper_binary(pam_handle_t *pamh, const char *helper,
                             const char *passwd, int service_specific);

#endif /* _PAM_CC_H_ */

