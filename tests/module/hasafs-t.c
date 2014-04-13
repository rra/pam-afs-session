/*
 * Test handling of k_hasafs failure.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <syslog.h>

#include <tests/fakepam/pam.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>

/* Provided by the fakekafs layer. */
extern int fakekafs_hasafs;


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
    char *skipping;
    struct pam_conv conv = { NULL, NULL };
    const char *debug_desc = debug ? " w/debug" : "";
    const char *argv[] = { "debug", NULL };

    if (asprintf(&skipping, "%d skipping, AFS apparently not available",
                 LOG_ERR) < 0)
        sysbail("cannot allocate memory");

    /* Claim that AFS doesn't exist and make sure we get the correct output. */
    fakekafs_hasafs = 0;
    status = pam_start("test", "test", &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    TEST_PAM(pam_sm_authenticate, 0, argv, "", PAM_SUCCESS,
             "not available");
    TEST_PAM(pam_sm_setcred, 0, argv, skipping, PAM_SUCCESS,
             "not available");
    TEST_PAM(pam_sm_setcred, PAM_DELETE_CRED, argv, skipping, PAM_SUCCESS,
             "not available");
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv, skipping,
             PAM_SUCCESS, "not available");
    TEST_PAM(pam_sm_setcred, PAM_REFRESH_CRED, argv, skipping, PAM_SUCCESS,
             "not available");
    TEST_PAM(pam_sm_open_session, 0, argv, skipping, PAM_IGNORE,
             "not available");
    TEST_PAM(pam_sm_close_session, 0, argv, skipping, PAM_IGNORE,
             "not available");
    pam_end(pamh, status);

    free(skipping);
}


int
main(void)
{
    plan(14 * 2);

    run_tests(false);
    run_tests(true);

    return 0;
}
