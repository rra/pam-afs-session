/*
 * Test correct construction of PAGs.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <pwd.h>
#include <syslog.h>

#include <tests/fakepam/pam.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>

/* Provided by the fakekafs layer. */
extern int fakekafs_pag;
extern bool fakekafs_token;


/*
 * We run the entire test suite twice, once with debug disabled and once with
 * debug enabled.  This is the wrapper around all the test cases to enable
 * that without code duplication.
 */
static void
run_tests(bool debug)
{
    struct passwd *user;
    pam_handle_t *pamh;
    int status;
    char *running, *already, *destroy, *redo, *redo_debug;
    struct pam_conv conv = { NULL, NULL };
    const char *debug_desc = debug ? " w/debug" : "";

#ifdef HAVE_KRB5_AFSLOG
    const char *argv[] = { "debug", NULL };
#else
    char *program;
    char *aklog = test_file_path ("data/fake-aklog");
    const char *argv[] = { "program=", "debug", NULL };
#endif

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);

    /*
     * If we don't have krb5_afslog, make sure we don't run the real aklog.
     * It might fail or overwrite the user's current tokens, both of which
     * would mess up the test.
     *
     * Build the messages appropriate to whichever version we're going to be
     * running.
     */
#ifdef HAVE_KRB5_AFSLOG
    if (asprintf(&running, "%d obtaining tokens for UID %lu", LOG_DEBUG,
                 (unsigned long) getuid()) < 0)
        sysbail("cannot allocate memory");
#else
    if (asprintf(&program, "program=%s", aklog) < 0)
        sysbail("cannot allocate memory");
    argv[0] = program;
    if (asprintf(&running, "%d running %s as UID %lu", LOG_DEBUG, aklog,
                 (unsigned long) getuid()) < 0)
        sysbail("cannot allocate memory");
#endif

    /* Other common messages. */
    if (asprintf(&already, "%d skipping, apparently already ran",
                 LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&destroy, "%d destroying tokens", LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&redo, "%d PAG apparently lost, recreating", LOG_NOTICE) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&redo_debug, "%d PAG apparently lost, recreating%s",
                 LOG_NOTICE, running) < 0)
        sysbail("cannot allocate memory");

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
    TEST_PAM(pam_sm_open_session, 0, argv,
             (debug ? running : ""), PAM_SUCCESS,
             "normal");
    is_int(1, fakekafs_pag, "created a new PAG");
#ifdef HAVE_KRB5_AFSLOG
    ok(fakekafs_token, "obtained tokens");
#else
    skip("krb5_afslog not available");
#endif
    fakekafs_token = false;
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv,
             (debug ? running : ""), PAM_SUCCESS,
             "normal reinitialize");
    is_int(1, fakekafs_pag, "stayed in the same PAG");
#ifdef HAVE_KRB5_AFSLOG
    ok(fakekafs_token, "obtained new tokens");
#else
    skip("krb5_afslog not available");
#endif
    fakekafs_token = true;
    TEST_PAM(pam_sm_close_session, 0, argv,
             (debug ? destroy : ""), PAM_SUCCESS,
             "normal");
    is_int(1, fakekafs_pag, "still in the PAG");
    ok(!fakekafs_token, "removed the token");
    fakekafs_token = false;

    /*
     * Test re-entering setcred inside the same PAM after a close.  This tests
     * whether we clean up our module-specific data properly on close
     * sesssion.
     */
    TEST_PAM(pam_sm_setcred, 0, argv,
             (debug ? running : ""), PAM_SUCCESS,
             "re-enter");
    is_int(2, fakekafs_pag, "moved to a new PAG");
#ifdef HAVE_KRB5_AFSLOG
    ok(fakekafs_token, "obtained tokens");
#else
    skip("krb5_afslog not available");
#endif
    fakekafs_token = true;

    /* Running setcred again will do nothing. */
    TEST_PAM(pam_sm_setcred, 0, argv,
             (debug ? already : ""), PAM_SUCCESS,
             "already run");
    is_int(2, fakekafs_pag, "stayed in the same PAG");
    ok(fakekafs_token, "token status didn't change");

    /*
     * Remove the PAG, and make sure that calling setcred will re-establish
     * it.
     */
    fakekafs_pag = 0;
    fakekafs_token = false;
    TEST_PAM(pam_sm_setcred, 0, argv,
             (debug ? redo_debug : redo), PAM_SUCCESS,
             "lost PAG");
    is_int(1, fakekafs_pag, "re-established the PAG");
#ifdef HAVE_KRB5_AFSLOG
    ok(fakekafs_token, "obtained tokens");
#else
    skip("krb5_afslog not available");
#endif
    fakekafs_token = true;

    /*
     * Running open_session now will do nothing, but if we remove the PAG, it
     * will also recreate the PAG and get tokens.
     */
    TEST_PAM(pam_sm_open_session, 0, argv,
             (debug ? already : ""), PAM_SUCCESS,
             "already run");
    is_int(1, fakekafs_pag, "stayed in the same PAG");
    ok(fakekafs_token, "token status didn't change");
    fakekafs_pag = 0;
    fakekafs_token = false;
    TEST_PAM(pam_sm_open_session, 0, argv,
             (debug ? redo_debug : redo), PAM_SUCCESS,
             "lost PAG");
    is_int(1, fakekafs_pag, "re-established the PAG");
#ifdef HAVE_KRB5_AFSLOG
    ok(fakekafs_token, "obtained tokens");
#else
    skip("krb5_afslog not available");
#endif

    /* Clean up. */
    pam_end(pamh, 0);
    unlink("aklog-args");
    free(running);
    free(already);
    free(destroy);
    free(redo);
    free(redo_debug);
#ifndef HAVE_KRB5_AFSLOG
    test_file_path_free(aklog);
    free(program);
#endif
}


int
main(void)
{
#ifdef NO_PAG_SUPPORT
    skip_all("no PAG support");
#endif

    plan(32 * 2);

    run_tests(false);
    run_tests(true);

    return 0;
}
