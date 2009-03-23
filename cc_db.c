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

#ifdef HAVE_DB_H
#include <db.h>
#endif

#include "cc_private.h"

static int _pam_cc_db_lock(void *_db, int operation);
static int _pam_cc_db_sync(void *_db);

#if DB_VERSION_MAJOR <= 2
#define USE_FLOCK	1
#else
/* XXX how do we enable locking here? */
#define USE_FLOCK	1
#endif

#ifndef DB_NOTFOUND
#define DB_NOTFOUND	1
#endif

/* Open an underlying datastore */
int pam_cc_db_open(const char *filename, unsigned int flags,
		   int mode, void **db_p)
{
	DB *db;
	unsigned int db_flags = 0;

#if DB_VERSION_MAJOR > 2
	int rc;

	if (flags & CC_DB_FLAGS_WRITE) {
		db_flags |= DB_CREATE;
	}
	if (flags & CC_DB_FLAGS_READ) {
		db_flags |= DB_RDONLY;
	}

	rc = db_create(&db, NULL, 0);
	if (rc != 0) {
		errno = rc;
		return PAM_SERVICE_ERR;
	}

#if (DB_VERSION_MAJOR > 3) && (DB_VERSION_MINOR > 0)
	rc = db->open(db, NULL, filename, NULL,
		      DB_BTREE, db_flags, mode);
#else
	rc = db->open(db, filename, NULL,
		      DB_BTREE, db_flags, mode);
#endif

	if (rc != 0) {
		db->close(db, 0);
		errno = rc;
		return PAM_SERVICE_ERR;
	}

#elif DB_VERSION_MAJOR == 2
	int rc;

	if (flags & CC_DB_FLAGS_WRITE) {
		db_flags |= DB_CREATE;
	}
	if (flags & CC_DB_FLAGS_READ) {
		db_flags |= DB_RDONLY;
	}

	rc = db_open(filename, DB_BTREE, db_flags, mode, NULL, NULL, &db);
	if (rc != 0) {
		errno = rc;
		return PAM_SERVICE_ERR;
	}
#else
	if (flags & CC_DB_FLAGS_WRITE) {
		db_flags |= O_CREAT;
	}
	if (flags & CC_DB_FLAGS_READ) {
		db_flags |= O_RDONLY;
	}
	db = dbopen(filename, db_flags, mode, DB_BTREE, NULL);
	if (db == NULL) {
		return PAM_SERVICE_ERR;
	}
#endif /* DB_VERSION_MAJOR > 2 */

	*db_p = (void *)db;

	return PAM_SUCCESS;
}

/* Write to underlying datastore */  
int pam_cc_db_put(void *_db, const char *keyname, size_t keylength,
		  const char *data, size_t size)
{
	DB *db = (DB *)_db;
	DBT key;
	DBT val;
	int rc;

	memset(&key, 0, sizeof(key));
	key.data = (char *)keyname;
	key.size = keylength;

	memset(&val, 0, sizeof(val));
	val.data = (char *)data;
	val.size = size;

#if USE_FLOCK
	rc = _pam_cc_db_lock(db, LOCK_EX);
	if (rc != PAM_SUCCESS) {
		return rc;
	}
#endif

	rc = db->put(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, &val, 0);
	if (rc == 0) {
		rc = _pam_cc_db_sync(db);
	} else {
		fprintf(stderr, "%s\n", strerror(rc));
#if DB_VERSION_MAJOR >= 2
		errno = rc;
#endif
		rc = PAM_SERVICE_ERR;
	}

#if USE_FLOCK
	_pam_cc_db_lock(db, LOCK_UN);
#endif

	return rc;
}

/* Read from underlying datastore */
int pam_cc_db_get(void *_db, const char *keyname, size_t keylength,
		  char *data, size_t *size)
{
	DB *db = (DB *)_db;
	DBT key;
	DBT val;
	int rc;

	memset(&key, 0, sizeof(key));
	key.data = (char *)keyname;
	key.size = keylength;

	memset(&val, 0, sizeof(val));

#if USE_FLOCK
	rc = _pam_cc_db_lock(db, LOCK_SH);
	if (rc != PAM_SUCCESS) {
		return rc;
	}
#endif

	rc = db->get(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, &val, 0);

#if USE_FLOCK
	_pam_cc_db_lock(db, LOCK_UN);
#endif

	if (rc != 0) {
#if DB_VERSION_MAJOR >= 2
		if (rc != DB_NOTFOUND)
			errno = rc;
#endif
		return (rc == DB_NOTFOUND) ? PAM_AUTHINFO_UNAVAIL : PAM_SERVICE_ERR;
	}

	if (val.size > *size) {
		return PAM_BUF_ERR;
	}

	memcpy(data, val.data, val.size);
	*size = val.size;

	return PAM_SUCCESS;
}

int pam_cc_db_delete(void *_db, const char *keyname, size_t keylength)
{
	DB *db = (DB *)_db;
	DBT key;
	int rc;

	memset(&key, 0, sizeof(key));
	key.data = (char *)keyname;
	key.size = keylength;

#if USE_FLOCK
	rc = _pam_cc_db_lock(db, LOCK_EX);
	if (rc != PAM_SUCCESS) {
		return rc;
	}
#endif

	rc = db->del(db,
#if DB_VERSION_MAJOR >= 2
		NULL,
#endif
		&key, 0);
	if (rc == 0) {
		rc = _pam_cc_db_sync(db);
	} else {
#if DB_VERSION_MAJOR >= 2
		if (rc != DB_NOTFOUND)
			errno = rc;
#endif
		return (rc == DB_NOTFOUND) ? PAM_AUTHINFO_UNAVAIL : PAM_SERVICE_ERR;
	}

#if USE_FLOCK
	_pam_cc_db_lock(db, LOCK_UN);
#endif

	return rc;
}

/* Close underlying datastore */
int pam_cc_db_close(void **db_p)
{
	DB *db;

	if (*db_p != NULL) {
		db = *db_p;

		if (db != NULL) {
#if DB_VERSION_MAJOR >= 2
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
	DB *db = (DB *)_db;
	int fd;

#if DB_VERSION_MAJOR >= 2
	int rc;

	rc = db->fd(db, &fd);
	if (rc != 0) {
		return PAM_SERVICE_ERR;
	}
#else
	fd = db->fd(db);
#endif /* DB_VERSION_MAJOR >= 2 */
	if (fd < 0) {
		return PAM_SERVICE_ERR;
	}

	if (flock(fd, operation) != 0) {
		return PAM_AUTHTOK_LOCK_BUSY;
	}

	return PAM_SUCCESS;
}

static int _pam_cc_db_sync(void *_db)
{
	DB *db = (DB *)_db;
	int rc;

	rc = db->sync(db, 0);

	return (rc == 0) ? PAM_SUCCESS : PAM_AUTHINFO_UNAVAIL;	
}

int pam_cc_db_seq(void *_db, void **cookie,
		  const char **key_p, size_t *keylength_p,
		  const char **data_p, size_t *datalength_p)
{
	DB *db = (DB *)_db;
	DBT key;
	DBT val;
	int rc;
#if DB_VERSION_MAJOR >= 2
	DBC *cursor = (DBC *)*cookie;
	int first = 0;
#endif

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

#if DB_VERSION_MAJOR < 2
	rc = db->seq(db, &key, &val, (*cookie == NULL ? R_FIRST : R_NEXT));
	if (*cookie == NULL) {
		*cookie = (void *)1;
	}
#else
	if (cursor == NULL) {
# if DB_VERSION_MAJOR > 2 || (DB_VERSION_MAJOR == 2 && DB_VERSION_MINOR > 5)
		rc = db->cursor(db, NULL, &cursor, 0);
# else
		rc = db->cursor(db, NULL, &cursor);
# endif
		if (rc != 0) {
			errno = rc;
			return PAM_SERVICE_ERR;
		}

		*cookie = cursor;
		first++;
	}

	rc = cursor->c_get(cursor, &key, &val,
			   first ? DB_FIRST : DB_NEXT);
#endif /* DB_VERSION_MAJOR <= 2 */

	switch (rc) {
	case DB_NOTFOUND:
		rc = PAM_SUCCESS;
		break;
	case 0:
		rc = PAM_INCOMPLETE;
		break;
	default:
		errno = rc;
		rc = PAM_SERVICE_ERR;
		return rc;
		break;
	}

	*key_p = key.data;
	*keylength_p = key.size;

	*data_p = val.data;
	*datalength_p = val.size;

	return rc;
}

