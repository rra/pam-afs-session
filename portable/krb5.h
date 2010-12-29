/*
 * Portability wrapper around krb5.h.
 *
 * This header includes krb5.h and then adjusts for various portability
 * issues, primarily between MIT Kerberos and Heimdal, so that code can be
 * written to a consistent API.
 *
 * Unfortunately, due to the nature of the differences between MIT Kerberos
 * and Heimdal, it's not possible to write code to either one of the APIs and
 * adjust for the other one.  In general, this header tries to make available
 * the Heimdal API and fix it for MIT Kerberos, but there are places where MIT
 * Kerberos requires a more specific call.  For those cases, it provides the
 * most specific interface.
 *
 * For example, MIT Kerberos has krb5_free_unparsed_name() whereas Heimdal
 * prefers the generic krb5_xfree().  In this case, this header provides
 * krb5_free_unparsed_name() for both APIs since it's the most specific call.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#ifndef PORTABLE_KRB5_H
#define PORTABLE_KRB5_H 1

/*
 * Allow inclusion of config.h to be skipped, since sometimes we have to use a
 * stripped-down version of config.h with a different name.
 */
#ifndef CONFIG_H_INCLUDED
# include <config.h>
#endif
#include <portable/macros.h>

#include <krb5.h>
#include <stdlib.h>

BEGIN_DECLS

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

/*
 * AIX included Kerberos includes the profile library but not the
 * krb5_appdefault functions, so we provide replacements that we have to
 * prototype.
 */
#ifndef HAVE_KRB5_APPDEFAULT_STRING
void krb5_appdefault_boolean(krb5_context, const char *, const krb5_data *,
                             const char *, int, int *);
void krb5_appdefault_string(krb5_context, const char *, const krb5_data *,
                            const char *, const char *, char **);
#endif

/* MIT-specific.  The Heimdal documentation says to use free(). */
#ifndef HAVE_KRB5_FREE_DEFAULT_REALM
# define krb5_free_default_realm(c, r) free(r)
#endif

/*
 * krb5_{get,free}_error_message are the preferred APIs for both current MIT
 * and current Heimdal, but there are tons of older APIs we may have to fall
 * back on for earlier versions.
 *
 * This function should be called immediately after the corresponding error
 * without any intervening Kerberos calls.  Otherwise, the correct error
 * message and supporting information may not be returned.
 */
#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
const char *krb5_get_error_message(krb5_context, krb5_error_code);
#endif
#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
void krb5_free_error_message(krb5_context, const char *);
#endif

/*
 * MIT-specific.  Heimdal automatically ignores environment variables if
 * called in a setuid context.
 */
#ifndef HAVE_KRB5_INIT_SECURE_CONTEXT
# define krb5_init_secure_context(c) krb5_init_context(c)
#endif

/* Undo default visibility change. */
#pragma GCC visibility pop

#endif /* !PORTABLE_KRB5_H */
