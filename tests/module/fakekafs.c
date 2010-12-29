/*
 * Fake kafs library used for testing.
 *
 * This source file provides an implementation of the kafs API that doesn't do
 * anything other than change internal state that can be queried.  It's used
 * for testing that the module makes the correct AFS calls.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#ifdef HAVE_KERBEROS
# include <portable/krb5.h>
#endif
#include <portable/system.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))

/* The current PAG number or 0 if we're not in a PAG. */
int fakekafs_pag = 0;

/* Whether we've obtained tokens since the last time we changed PAGs. */
bool fakekafs_token = false;


/*
 * Always return true and say we have AFS.
 */
int
k_hasafs(void)
{
    return 1;
}


/*
 * Return true if we're currently in a PAG, false otherwise.
 */
int
k_haspag(void)
{
    return fakekafs_pag != 0;
}


/*
 * Provide k_pioctl since it's part of the interface, but always return -1 and
 * set errno to ENOSYS.
 */
int
k_pioctl(char *path UNUSED, int call UNUSED, struct ViceIoctl *data UNUSED,
         int follow UNUSED)
{
    errno = ENOSYS;
    return -1;
}


/*
 * Enter a new PAG.  We can do this by just incrementing the PAG number.
 * Always returns 0, indicating no error.
 */
int
k_setpag(void)
{
    fakekafs_pag++;
    return 0;
}


/*
 * Remove the tokens from a PAG.
 */
int
k_unlog(void)
{
    fakekafs_token = false;
    return 0;
}


/*
 * Obtain tokens in a PAG.  We support several versions of this function: all
 * the ones that can be called by the krb5_afslog support.  Since these
 * functions are prototyped to take Kerberos data types, they're only
 * available if built with Kerberos support.
 */
#ifdef HAVE_KERBEROS
krb5_error_code
krb5_afslog_uid(krb5_context context UNUSED, krb5_ccache id UNUSED,
                const char *cell UNUSED, krb5_const_realm realm UNUSED,
                uid_t uid UNUSED)
{
    fakekafs_token = true;
    return 0;
}

krb5_error_code
krb5_afslog_uid_home(krb5_context context UNUSED, krb5_ccache id UNUSED,
                     const char *cell UNUSED, krb5_const_realm realm UNUSED,
                     uid_t uid UNUSED, const char *homedir UNUSED)
{
    fakekafs_token = true;
    return 0;
}
#endif /* HAVE_KERBEROS */
