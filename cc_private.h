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
	char *service;
	char *user;
	const struct pam_conv *conv;
	char *ccredsfile;
	void *db;
};

/* Open an underlying datastore */
int pam_cc_db_open(const char *filename, unsigned int flags, int mode, void **db);

/* Write to underlying datastore */  
int pam_cc_db_put(void *db, char *key, size_t keylength, char *data, size_t length);

/* Read from underlying datastore */
int pam_cc_db_get(void *db, char *key, size_t keylength, char *data, size_t *length);

/* Delete from underlying datastore */
int pam_cc_db_delete(void *db, char *key, size_t keylength);

/* Close underlying datastore */
int pam_cc_db_close(void **db);

#if DB_VERSION_MAJOR <= 2
/* flags */
#define DB_CREATE			(O_RDWR | O_CREAT)
#define DB_RDONLY			(O_RDONLY)
#define DB_AUTO_COMMIT			0
#endif

#define CC_DB_FLAGS_WRITE		(DB_CREATE | DB_AUTO_COMMIT)
#define CC_DB_FLAGS_READ		DB_RDONLY
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

