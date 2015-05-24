/*
 * Test correct construction of PAGs.
 *
 * This test doesn't check output because it's too difficult to do so at the
 * moment without using the scripted testing.  When that library has enough
 * hooks to examine internal state at every point, output testing can be
 * re-added.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2015 Russ Allbery <eagle@eyrie.org>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <pwd.h>

#include <tests/fakepam/pam.h>
#include <tests/tap/basic.h>

/* Provided by the fakekafs layer. */
extern int fakekafs_pag;
extern bool fakekafs_token;

/* Can only check tokens if we have krb5_afslog. */
#ifdef HAVE_KRB5_AFSLOG
# define TEST_TOKENS() ok(fakekafs_token, "obtained tokens")
#else
# define TEST_TOKENS() skip("krb5_afslog not available")
#endif


int
main(void)
{
    struct passwd *user;
    pam_handle_t *pamh;
    int status;
    struct pam_conv conv = { NULL, NULL };

    /* Arguments depend on whether we were built with Heimdal. */
#ifdef HAVE_KRB5_AFSLOG
    int argc = 0;
    const char *argv[] = { NULL };
#else
    char *program;
    char *aklog = test_file_path ("data/fake-aklog");
    int argc = 1;
    const char *argv[] = { "program=", NULL };
#endif

    /* Skip this test if built without PAG support. */
#ifdef NO_PAG_SUPPORT
    skip_all("no PAG support");
#endif

    /* Set up the plan. */
    plan(24);

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);

    /*
     * If we don't have krb5_afslog, make sure we don't run the real aklog.
     * It might fail or overwrite the user's current tokens, both of which
     * would mess up the test.
     */
#ifndef HAVE_KRB5_AFSLOG
    if (asprintf(&program, "program=%s", aklog) < 0)
        sysbail("cannot allocate memory");
    argv[0] = program;
#endif

    /*
     * Test opening a session and make sure we get a PAG and a token, test
     * reinitialize, and then make sure closing the session makes the token go
     * away.
     */
    fakekafs_pag = 0;
    fakekafs_token = false;
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    status = pam_sm_open_session(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "open session");
    is_int(1, fakekafs_pag, "created a new PAG");
    TEST_TOKENS();
    fakekafs_token = false;
    status = pam_sm_setcred(pamh, PAM_REINITIALIZE_CRED, argc, argv);
    is_int(PAM_SUCCESS, status, "setcred reinitialize");
    is_int(1, fakekafs_pag, "stayed in the same PAG");
    TEST_TOKENS();
    fakekafs_token = true;
    status = pam_sm_close_session(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "close session");
    is_int(1, fakekafs_pag, "still in the PAG");
    ok(!fakekafs_token, "removed the token");
    fakekafs_token = false;

    /*
     * Test re-entering setcred inside the same PAM after a close.  This tests
     * whether we clean up our module-specific data properly on close
     * sesssion.
     */
    status = pam_sm_setcred(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "setcred");
    is_int(2, fakekafs_pag, "moved to a new PAG");
    TEST_TOKENS();
    fakekafs_token = true;

    /* Running setcred again will do nothing. */
    status = pam_sm_setcred(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "setcred already ran");
    is_int(2, fakekafs_pag, "stayed in the same PAG");
    ok(fakekafs_token, "token status didn't change");

    /*
     * Remove the PAG, and make sure that calling setcred will re-establish
     * it.
     */
    fakekafs_pag = 0;
    fakekafs_token = false;
    status = pam_sm_setcred(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "setcred without PAG");
    is_int(1, fakekafs_pag, "re-established the PAG");
    TEST_TOKENS();
    fakekafs_token = true;

    /*
     * Running open_session now will do nothing, but if we remove the PAG, it
     * will also recreate the PAG and get tokens.
     */
    status = pam_sm_open_session(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "open session already ran");
    is_int(1, fakekafs_pag, "stayed in the same PAG");
    ok(fakekafs_token, "token status didn't change");
    fakekafs_pag = 0;
    fakekafs_token = false;
    status = pam_sm_open_session(pamh, 0, argc, argv);
    is_int(PAM_SUCCESS, status, "open session without PAG");
    is_int(1, fakekafs_pag, "re-established the PAG");
    TEST_TOKENS();

    /* Clean up. */
    pam_end(pamh, 0);
    unlink("aklog-args");
#ifndef HAVE_KRB5_AFSLOG
    test_file_path_free(aklog);
    free(program);
#endif
    return 0;
}
