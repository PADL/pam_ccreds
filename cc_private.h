/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#ifndef _PAM_CC_PRIVATE_H_
#define _PAM_CC_PRIVATE_H_ 1	                                                                                   
/*
 * PAM Cached Credentials library
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

struct pam_cc_handle {
	unsigned int flags;
	char *service;
	char *user;
	const struct pam_conv *conv;
	char *ccredsfile;
	void *db;
};

/* Open an underlying datastore */
int pam_cc_db_open(const char *filename, unsigned int flags, int mode, void **db);

/* Write to underlying datastore */  
int pam_cc_db_put(void *db, const char *key, size_t keylength,
		  const char *data, size_t length);

/* Read from underlying datastore */
int pam_cc_db_get(void *db, const char *key, size_t keylength,
		  char *data, size_t *length);

/* Delete from underlying datastore */
int pam_cc_db_delete(void *db, const char *key, size_t keylength);

/* Close underlying datastore */
int pam_cc_db_close(void **db);

/* Enumerate values in datastore */
int pam_cc_db_seq(void *_db, void **cookie,
		  const char **key_p, size_t *keylength_p,
		  const char **data_p, size_t *datalength_p);

#define CC_DB_FLAGS_WRITE		0x01
#define CC_DB_FLAGS_READ		0x02

#define CC_DB_MODE			(S_IREAD | S_IWRITE)

#define PADL_CC_HANDLE_DATA		"PADL-CC-HANDLE-DATA"

#include "cc.h"

typedef int (*pam_cc_key_derivation_function_t)(pam_cc_handle_t *,
						pam_cc_type_t,
						const char *,
						size_t,
						char **,
						size_t *);

#endif /* _PAM_CC_PRIVATE_H_ */

