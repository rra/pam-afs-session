/*
 * Basic tests for the pam-afs-session module.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <pwd.h>
#include <syslog.h>

#include <tests/fakepam/testing.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>


/*
 * We run the entire test suite twice, once with debug disabled and once with
 * debug enabled.  This is the wrapper around all the test cases to enable
 * that without code duplication.
 */
static void
run_tests(bool debug)
{
    pam_handle_t *pamh;
    int status;
    char *skipping, *skiptokens, *skipsession, *program, *running, *already;
    char *destroy;
    char *aklog = test_file_path ("data/fake-aklog");
    struct passwd *user;
    struct pam_conv conv = { NULL, NULL };
    const char *debug_desc = debug ? " w/debug" : "";
    const char *argv_nothing[] = { "nopag", "notokens", "debug", NULL };
    const char *argv_normal[] = { "program=", "debug", NULL };

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");

    /* Build some messages that we'll use multiple times. */
    if (asprintf(&skipping, "%d skipping as configured", LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&skiptokens, "%d skipping tokens, no Kerberos ticket cache",
                 LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&skipsession, "%d skipping, no open session", LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&program, "program=%s", aklog) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&running, "%d running %s as UID %lu", LOG_DEBUG, aklog,
                 (unsigned long) getuid()) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&already, "%d skipping, apparently already ran",
                 LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");
    if (asprintf(&destroy, "%d destroying tokens", LOG_DEBUG) < 0)
        sysbail("cannot allocate memory");

    /* Do nothing and check for correct output status. */
    status = pam_start("test", "testuser", &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    TEST_PAM(pam_sm_authenticate, 0, argv_nothing,
             "", PAM_SUCCESS,
             "do nothing");
    TEST_PAM(pam_sm_setcred, 0, argv_nothing,
             "", PAM_SUCCESS,
             "do nothing");
    TEST_PAM(pam_sm_setcred, PAM_DELETE_CRED, argv_nothing,
             (debug ? skipping : ""), PAM_IGNORE,
             "delete do nothing");
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv_nothing,
             "", PAM_SUCCESS,
             "reinitialize do nothing");
    TEST_PAM(pam_sm_setcred, PAM_REFRESH_CRED, argv_nothing,
             "", PAM_SUCCESS,
             "refresh do nothing");
    TEST_PAM(pam_sm_open_session, 0, argv_nothing,
             "", PAM_SUCCESS,
             "do nothing");
    TEST_PAM(pam_sm_close_session, 0, argv_nothing,
             (debug ? skipping : ""), PAM_IGNORE,
             "do nothing");
    pam_end(pamh, status);

    /*
     * Test behavior without a Kerberos ticket.  This doesn't test actual
     * creation of a PAG.
     */
    unlink("aklog-args");
    status = pam_start("test", "testuser", &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    argv_normal[0] = program;
    TEST_PAM(pam_sm_authenticate, 0, argv_normal,
             "", PAM_SUCCESS,
             "no ticket");
    TEST_PAM(pam_sm_setcred, 0, argv_normal,
             (debug ? skiptokens : ""), PAM_SUCCESS,
             "no ticket");
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv_normal,
             (debug ? skiptokens : ""), PAM_SUCCESS,
             "reinitialize no ticket");
    TEST_PAM(pam_sm_setcred, PAM_REFRESH_CRED, argv_normal,
             (debug ? skiptokens : ""), PAM_SUCCESS,
             "refresh no ticket");
    TEST_PAM(pam_sm_open_session, 0, argv_normal,
             (debug ? skiptokens : ""), PAM_SUCCESS,
             "no ticket");
    TEST_PAM(pam_sm_close_session, 0, argv_normal,
             (debug ? skipsession : ""), PAM_SUCCESS,
             "no ticket");
    pam_end(pamh, status);
    ok(access("aklog-args", F_OK) < 0, "aklog was not run");

    /*
     * Fake the presence of a Kerberos ticket and see that aklog runs, and
     * test suppression of multiple calls to pam_sm_setcred.
     */
    unlink("aklog-args");
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_setcred, 0, argv_normal,
             (debug ? running : ""), PAM_SUCCESS,
             "normal");
    ok(access("aklog-args", F_OK) == 0, "aklog was run");
    unlink("aklog-args");
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv_normal,
             (debug ? running : ""), PAM_SUCCESS,
             "normal reinitialize");
    ok(access("aklog-args", F_OK) == 0, "aklog was run");
    unlink("aklog-args");
    TEST_PAM(pam_sm_setcred, PAM_REFRESH_CRED, argv_normal,
             (debug ? running : ""), PAM_SUCCESS,
             "normal refresh");
    ok(access("aklog-args", F_OK) == 0, "aklog was run");
    unlink("aklog-args");
    TEST_PAM(pam_sm_setcred, 0, argv_normal,
             (debug ? already : ""), PAM_SUCCESS,
             "normal");
    ok(access("aklog-args", F_OK) < 0, "aklog was not run");
    TEST_PAM(pam_sm_close_session, 0, argv_normal,
             (debug ? destroy : ""), PAM_SUCCESS,
             "normal");
    pam_end(pamh, status);

    test_file_path_free(aklog);
    free(program);
    free(skipping);
    free(skiptokens);
    free(skipsession);
    free(running);
    free(already);
    free(destroy);
}


int
main(void)
{
    if (!k_hasafs())
        skip_all("AFS not available");

    plan(41 * 2);

    run_tests(false);
    run_tests(true);

    return 0;
}
