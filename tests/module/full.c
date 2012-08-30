/*
 * Test suite for full pam-afs-session functionality.
 *
 * This is the backend program used to test pam-afs-session all the way
 * through creation of a PAG and obtaining tokens.  It therefore requires a
 * working Kerberos and AFS setup on the local system running the test suite.
 *
 * This test case first checks if k_hasafs returns true.  If it doesn't, it
 * exits with status 2, indicating that all tests should be skipped.  Also
 * bail if we can't find the user's ticket cache.
 *
 * If AFS is available, it shows token output before and after opening a
 * session, and then again after closing the session (which should destroy any
 * tokens).  If any of the PAM calls fail, it reports an error to standard
 * error and exits with status 1.  If all commands succeed, it exits 0.
 *
 * If tokens cannot be obtained because aklog (or the equivalent) doesn't
 * work, it exits with status 3.
 *
 * If something goes wrong outside of the PAM calls that means a fatal error
 * for the test, it exits with status 4.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#ifdef HAVE_KERBEROS
# include <portable/krb5.h>
#endif
#include <portable/pam.h>
#include <portable/system.h>

#include <errno.h>
#include <pwd.h>

#include <tests/fakepam/pam.h>


/*
 * Copy the Kerberos ticket cache setting into the PAM environment.  If built
 * with Kerberos support, we can do this the clean way that doesn't require
 * KRB5CCNAME already be set.  Otherwise, we have to hope that the user is
 * using the environment variable; otherwise, we have to bail.
 */
static void
copy_krb5_env(pam_handle_t *pamh)
{
    const char *cache = NULL;
    char *env;

#ifdef HAVE_KERBEROS
    krb5_error_code status;
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;

    status = krb5_init_context(&ctx);
    if (status == 0)
        status = krb5_cc_default(ctx, &ccache);
    if (status == 0)
        cache = krb5_cc_get_name(ctx, ccache);
#endif

    if (cache == NULL)
        cache = getenv("KRB5CCNAME");
    if (cache == NULL) {
        fprintf(stderr, "cannot get name of Kerberos ticket cache\n");
        exit(3);
    }
    if (asprintf(&env, "KRB5CCNAME=%s", cache) < 0) {
        fprintf(stderr, "cannot allocate memory: %s\n", strerror(errno));
        exit(4);
    }
    if (pam_putenv(pamh, env) != PAM_SUCCESS) {
        fprintf(stderr, "cannot set PAM environment variable\n");
        exit(4);
    }

#ifdef HAVE_KERBEROS
    if (ctx != NULL) {
        if (ccache != NULL)
            krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
    }
#endif
}


/*
 * Test whether we can obtain tokens using either an external program or
 * libkafs.  Exit with status 3 if we cannot.
 */
#ifdef HAVE_KRB5_AFSLOG
static void
test_aklog(void)
{
    krb5_error_code status;
    krb5_context ctx;
    krb5_ccache ccache;

    status = krb5_init_context(&ctx);
    if (status == 0)
        status = krb5_cc_default(ctx, &ccache);
    if (status == 0)
        status = krb5_afslog_uid(ctx, ccache, NULL, NULL, getuid());
    if (status != 0)
        exit(3);
}
#else /* !HAVE_KRB5_AFSLOG */
static void
test_aklog(void)
{
# ifndef PATH_AKLOG
    exit(3);
# endif
    if (system(PATH_AKLOG) != 0)
        exit(3);
}
#endif /* !HAVE_KRB5_AFSLOG */


int
main(void)
{
    pam_handle_t *pamh;
    int status;
    struct passwd *user;
    struct output *output;
    size_t i;
    struct pam_conv conv = { NULL, NULL };
    const char *argv[] = { NULL };

    /*
     * Skip the whole test if AFS isn't available or if we can't get tokens.
     */
    if (!k_hasafs())
        exit(2);
#ifdef NO_PAG_SUPPORT
    exit(2);
#endif
    if (k_setpag() != 0) {
        fprintf(stderr, "k_setpag failed: %s\n", strerror(errno));
        exit(4);
    }
    test_aklog();

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL) {
        fprintf(stderr, "cannot find username of current user\n");
        exit(4);
    }
    pam_set_pwd(user);

    /*
     * We have tokens at the start of the test.  Set up PAM and then open a
     * session, at which point we should still have tokens.  Then close the
     * session, and we should have no tokens.
     */
    printf("=== tokens (aklog) ===\n");
    fflush(stdout);
    if (system("tokens") != 0)
        fprintf(stderr, "tokens failed\n");
    if (k_unlog() != 0) {
        fprintf(stderr, "k_unlog failed: %s\n", strerror(errno));
        exit(4);
    }
    printf("=== tokens (before) ===\n");
    fflush(stdout);
    if (system("tokens") != 0)
        fprintf(stderr, "tokens failed\n");
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS) {
        fprintf(stderr, "cannot create PAM handle\n");
        exit(4);
    }
    copy_krb5_env(pamh);
    status = pam_sm_open_session(pamh, 0, 0, argv);
    if (status != PAM_SUCCESS)
        exit(1);
    printf("=== tokens (session) ===\n");
    fflush(stdout);
    if (system("tokens") != 0)
        fprintf(stderr, "tokens failed\n");
    status = pam_sm_close_session(pamh, 0, 0, argv);
    if (status != PAM_SUCCESS)
        exit(1);
    printf("=== tokens (after) ===\n");
    fflush(stdout);
    if (system("tokens") != 0)
        fprintf(stderr, "tokens failed\n");
    printf("=== output ===\n");
    output = pam_output();
    if (output != NULL) {
        for (i = 0; i < output->count; i++)
            printf("%d %s", output->lines[i].priority, output->lines[i].line);
        printf("\n");
    }
    pam_end(pamh, 0);

    return 0;
}
