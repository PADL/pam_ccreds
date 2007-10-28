/*
 * This program is designed to run setuid(root) or with sufficient
 * privilege to read the cached password database. It is designed
 * to provide a mechanism for the current user (defined by this
 * process' uid) to verify their own password.
 *
 * The password is read from the standard input. The exit status of
 * this program indicates whether the user is authenticated or not.
 *
 * Copyright information is located at the end of the file.
 *
 */

#ifdef MEMORY_DEBUG
# undef exit
# undef strdup
# undef free
#endif /* MEMORY_DEBUG */

#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>

#include "cc_private.h"

#define MAXPASS		200	/* the maximum length of a password */

#define CCREDS_PASSED	0
#define CCREDS_FAILED	1

/* syslogging function for errors and other information */

static void _log_err(int err, const char *format,...)
{
	va_list args;

	va_start(args, format);
	openlog("ccreds_chkpwd", LOG_CONS | LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static void su_sighandler(int sig)
{
#ifndef SA_RESETHAND
	/* emulate the behaviour of the SA_RESETHAND flag */
	if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV )
		signal(sig, SIG_DFL);
#endif
	if (sig > 0) {
		_log_err(LOG_NOTICE, "caught signal %d.", sig);
		exit(sig);
	}
}

static void setup_signals(void)
{
	struct sigaction action;	/* posix signal structure */

	/*
	 * Setup signal handlers
	 */
	(void) memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
	action.sa_flags = SA_RESETHAND;
#endif
	(void) sigaction(SIGILL, &action, NULL);
	(void) sigaction(SIGTRAP, &action, NULL);
	(void) sigaction(SIGBUS, &action, NULL);
	(void) sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	(void) sigaction(SIGTERM, &action, NULL);
	(void) sigaction(SIGHUP, &action, NULL);
	(void) sigaction(SIGINT, &action, NULL);
	(void) sigaction(SIGQUIT, &action, NULL);
}

static int _ccreds_verify_password(const char *service, const char *name,
                                   const char *ccredsfile, const char *p)
{
	int rc, retval = CCREDS_FAILED;
	pam_cc_handle_t *pamcch;

	rc = pam_cc_start(service, name, ccredsfile, CC_FLAGS_READ_ONLY,
	                  &pamcch);
	if (rc != PAM_SUCCESS) {
		_log_err(LOG_DEBUG, "error initializing");
		retval = CCREDS_FAILED;
		goto _return;
	}

	rc = pam_cc_validate_credentials(pamcch, PAM_CC_TYPE_DEFAULT, p,
	                                 strlen(p));
	if (rc != PAM_SUCCESS) {
		_log_err(LOG_DEBUG, "error reading cached credentials");
		retval = CCREDS_FAILED;
		goto _return;
	}

	retval = CCREDS_PASSED;

	pam_cc_end(&pamcch);

_return:
	return retval;
}

static char *getuidname(uid_t uid)
{
	struct passwd *pw;
	static char username[32];

	pw = getpwuid(uid);
	if (pw == NULL)
		return NULL;

	strncpy(username, pw->pw_name, sizeof(username));
	username[sizeof(username) - 1] = '\0';

	return username;
}

int main(int argc, char *argv[])
{
	char pass[MAXPASS + 1];
	int npass;
	int force_failure = 0;
	int retval = CCREDS_FAILED;
	char *user;
	char *user_arg;
	char *service;
	char *ccredsfile;

	/*
	 * Catch or ignore as many signal as possible.
	 */
	setup_signals();

	/*
	 * we establish that this program is running with non-tty stdin.
	 * this is to discourage casual use. It does *NOT* prevent an
	 * intruder from repeatadly running this program to determine the
	 * password of the current user (brute force attack, but one for
	 * which the attacker must already have gained access to the user's
	 * account).
	 */

	if (isatty(STDIN_FILENO)) {

		_log_err(LOG_NOTICE
		      ,"inappropriate use of ccreds helper binary [UID=%d,tty]"
			 ,getuid());
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return CCREDS_FAILED;
	}

	/*
	 * determine the current user's name is
	 */
	user = getuidname(getuid());

	if (argc < 2 || argc > 4) {
		_log_err(LOG_NOTICE
		      ,"inappropriate use of ccreds helper binary [UID=%d,bad argv]"
			 ,getuid());
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return CCREDS_FAILED;
	}

	user_arg = argv[1];
	service = (argc > 2) ? argv[2] : NULL;
	ccredsfile = (argc > 3) ? argv[3] : NULL;

	/* Verify that user matches */
        if (strcmp(user, user_arg)) {
	    force_failure = 1;
	}

	/* read the password from stdin (a pipe from the pam_ccreds module) */
	npass = read(STDIN_FILENO, pass, MAXPASS);

	if (npass < 0) {	/* is it a valid password? */
		_log_err(LOG_DEBUG, "no password supplied");
	} else if (npass >= MAXPASS) {
		_log_err(LOG_DEBUG, "password too long");
	} else {
		if (npass == 0) {
			/* the password is blank */
			retval = _ccreds_verify_password(service, user, ccredsfile, "");
		} else {
			/* does pass agree with the official one? */
			pass[npass] = '\0';	/* NUL terminate */
			retval = _ccreds_verify_password(service, user, ccredsfile, pass);
		}
	}
	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */
	if ((retval != CCREDS_PASSED) || force_failure) {
	    return CCREDS_FAILED;
	} else {
	    return CCREDS_PASSED;
	}
}

/*
 * This program is based on unix_chkpwd by Andrew G. Morgan.
 *
 * The modifications are Copyright (c) W. Michael Petullo, 2005.
 * All rights reserved.
 *
 * See below for the original unix_chkpwd copyright notice.
 *
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
