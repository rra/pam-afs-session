/*
 * Logging functions for pam-afs-session.
 *
 * Logs errors and debugging messages from pam-afs-session functions.  The
 * debug versions only log anything if debugging was enabled; the error
 * versions always log.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#ifdef HAVE_KERBEROS
# if !defined(HAVE_KRB5_GET_ERROR_MESSAGE) && !defined(HAVE_KRB5_GET_ERR_TEXT)
#  if defined(HAVE_IBM_SVC_KRB5_SVC_H)
#   include <ibm_svc/krb5_svc.h>
#  elif defined(HAVE_ET_COM_ERR_H)
#   include <et/com_err.h>
#  else
#   include <com_err.h>
#  endif
# endif

/*
 * This string is returned for unknown error messages.  We use a static
 * variable so that we can be sure not to free it.
 */
static const char error_unknown[] = "unknown error";
#endif

#include "internal.h"

/*
 * Basic error logging.  Log a message with LOG_ERR priority.
 */
void
pamafs_error(const char *fmt, ...)
{
    char msg[256];
    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    syslog(LOG_ERR, "(pam_afs_session): %s", msg);
}


/*
 * Log a generic debugging message only if debug is enabled.
 */
void
pamafs_debug(struct pam_args *pargs, const char *fmt, ...)
{
    char msg[256];
    va_list args;

    if (pargs == NULL || !pargs->debug)
        return;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    syslog(LOG_DEBUG, "(pam_afs_session): %s", msg);
}


/*
 * Log a Kerberos v5 failure with LOG_ERR priority.  We don't free the message
 * if we have no context under the assumption that no memory would be
 * allocated in that case.  This is true for the current MIT Kerberos
 * implementation.
 *
 * The error reporting functions keep changing, so we need all sorts of ugly
 * Autoconf cruft here to get the right ones.
 */
#ifdef HAVE_KERBEROS
static const char *
pamafs_get_krb5_error(krb5_context c, krb5_error_code code)
{
    const char *msg = NULL;

# if defined(HAVE_KRB5_GET_ERROR_MESSAGE)
    msg = krb5_get_error_message(c, code);
# elif defined(HAVE_KRB5_GET_ERR_TEXT)
    msg = krb5_get_err_text(c, code);
# elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_svc_get_msg(code, &msg);
# else
    msg = error_message(code);
# endif
    if (msg == NULL)
        return "unknown error";
    else
        return msg;
}

static void
pamafs_free_krb5_error(krb5_context c, const char *msg)
{
    if (msg == error_unknown)
        return;
# ifdef HAVE_KRB5_FREE_ERROR_MESSAGE
    krb5_free_error_message(c, msg);
# elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_free_string((char *) msg);
# endif
}

void
pamafs_error_krb5(krb5_context ctx, const char *msg, int status)
{
    const char *k5_msg = NULL;

    k5_msg = pamafs_get_krb5_error(ctx, status);
    pamafs_error("%s: %s", msg, k5_msg);
    if (ctx == NULL)
        pamafs_free_krb5_error(ctx, k5_msg);
}
#endif /* HAVE_KERBEROS */
