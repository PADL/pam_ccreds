/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

/*
 * Database library wrappers
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
#include <fcntl.h>

#include <sys/file.h>

#ifdef HAVE_DB3_DB_185_H
#include <db3/db_185.h>
#elif defined(HAVE_DB_185_H)
#include <db_185.h>
#elif defined(HAVE_DB1_DB_H)
#include <db1/db.h>
#elif defined(HAVE_DB_H)
#include <db.h>
#endif /* HAVE_DB3_DB_H */

#include "cc_private.h"

static int _pam_cc_db_lock(void *_db, int operation);
static int _pam_cc_db_sync(void *_db);

/* Open an underlying datastore */
int pam_cc_db_open(const char *filename, unsigned int flags, int mode, void **db_p)
{
	DB *db;
#if DB_VERSION_MAJOR > 2
	int rc;

	rc = db_create(&db, NULL, 0);
	if (rc != 0) {
		return PAM_SERVICE_ERR;
	}

#if (DB_VERSION_MAJOR > 3) && (DB_VERSION_MINOR > 0)
	rc = db->open(db, NULL, filename, NULL, DB_HASH, flags, mode);
#else
	rc = db->open(db, NULL, filename, DB_HASH, flags, mode);
#endif

	if (rc != 0) {
		db->close(db, 0);
		return PAM_SERVICE_ERR;
	}

#else
	db = dbopen(filename, flags, mode, DB_HASH, NULL);
	if (db == NULL) {
		return PAM_SERVICE_ERR;
	}
#endif /* DB_VERSION_MAJOR > 2 */

	*db_p = (void *)db;

	return PAM_SUCCESS;
}

/* Write to underlying datastore */  
int pam_cc_db_put(void *_db, char *keyname, size_t keylength, char *data, size_t size)
{
	DB *db = (DB *)_db;
	DBT key;
	DBT val;
	int rc;

	memset(&key, 0, sizeof(&key));
	key.data = keyname;
	key.size = keylength;

	memset(&val, 0, sizeof(&val));
	val.data = data;
	val.size = size;

	rc = _pam_cc_db_lock(db, LOCK_EX);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = ((db->put)(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, &val, 0) == 0) ? PAM_SUCCESS : PAM_SERVICE_ERR;
	if (rc == PAM_SUCCESS) {
		rc = _pam_cc_db_sync(db);
	}

	_pam_cc_db_lock(db, LOCK_UN);

	return rc;
}

/* Read from underlying datastore */
int pam_cc_db_get(void *_db, char *keyname, size_t keylength, char *data, size_t *size)
{
	DB *db = (DB *)_db;
	DBT key;
	DBT val;
	int rc;

	memset(&key, 0, sizeof(&key));
	key.data = keyname;
	key.size = keylength;

	memset(&val, 0, sizeof(&val));

	rc = _pam_cc_db_lock(db, LOCK_SH);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = (db->get)(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, &val, 0);

	_pam_cc_db_lock(db, LOCK_UN);

	if (rc != 0) {
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (val.size < *size) {
		return PAM_BUF_ERR;
	}

	memcpy(data, val.data, val.size);
	*size = val.size;

	return PAM_SUCCESS;
}

int pam_cc_db_delete(void *_db, char *keyname, size_t keylength)
{
	DB *db = (DB *)_db;
	DBT key;
	int rc;

	memset(&key, 0, sizeof(&key));
	key.data = keyname;
	key.size = keylength;

	/* use fnctl() locking */
	rc = _pam_cc_db_lock(db, LOCK_EX);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = ((db->del)(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, 0) == 0) ? PAM_SUCCESS : PAM_AUTHINFO_UNAVAIL;

	if (rc == PAM_SUCCESS) {
		rc = _pam_cc_db_sync(db);
	}

	_pam_cc_db_lock(db, LOCK_UN);

	return rc;
}

/* Close underlying datastore */
int pam_cc_db_close(void **db_p)
{
	DB *db;

	if (*db_p != NULL) {
		db = *db_p;

		if (db != NULL) {
#if DB_VERSION_MAJOR > 2
			db->close(db, 0);
#else
			db->close(db);
#endif /* DB_VERSION_MAJOR > 2 */
		}

		*db_p = NULL;
	}

	return PAM_SUCCESS;
}

static int _pam_cc_db_lock(void *_db, int operation)
{
#if DB_VERSION_MAJOR <= 2
	DB *db = (DB *)_db;
	int fd;

	fd = db->fd(db);
	if (fd < 0) {
		return PAM_SERVICE_ERR;
	}

	if (flock(fd, operation) != 0) {
		return PAM_AUTHTOK_LOCK_BUSY;
	}
#endif /* DB_VERSION_MAJOR > 2 */

	return PAM_SUCCESS;
}

static int _pam_cc_db_sync(void *_db)
{
	DB *db = (DB *)_db;
	int rc;

	rc = db->sync(db, 0);

	return (rc == 0) ? PAM_SUCCESS : PAM_AUTHINFO_UNAVAIL;	
}

