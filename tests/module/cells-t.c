/*
 * Test support of acquiring tokens for alternative cells.
 *
 * Also tests aklog given multiple arguments, since it was convenient to put
 * those tests here where the argument parsing code was already present.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2010, 2011
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

#include <tests/fakepam/pam.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>


/*
 * Check whether the arguments to aklog match what was expected and then
 * unlink the resulting file.
 */
static void
is_aklog_args(const char *expected)
{
    char buf[BUFSIZ];
    FILE *args;

    if (access("aklog-args", F_OK) == 0) {
        ok(1, "aklog run");
        args = fopen("aklog-args", "r");
        if (args == NULL)
            sysbail("cannot open aklog-args");
        if (fgets(buf, sizeof(buf), args) == NULL)
            sysbail("cannot read from aklog-args");
        buf[strlen(buf) - 1] = '\0';
        fclose(args);
        is_string(expected, buf, "aklog arguments");
    } else {
        ok(0, "aklog run");
        skip("aklog arguments");
    }
    unlink("aklog-args");
}


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
    char *program, *passing;
    struct pam_conv conv = { NULL, NULL };
    const char *debug_desc = debug ? " w/debug" : "";
    const char *argv_cellcomma[] =
        { "afs_cells=example.com,example.edu", "program=", "debug", NULL };
    const char *argv_cellspace[] =
        { "afs_cells=example.com , example.edu", "program=", "debug", NULL };
    char *aklog = test_file_path ("data/fake-aklog");

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);

    /* Build some messages that we'll use multiple times. */
    if (asprintf(&program, "program=%s", aklog) < 0)
        sysbail("cannot allocate memory");
    argv_cellcomma[1] = program;
    argv_cellspace[1] = program;
    if (asprintf(&passing, "%d passing -c example.com to aklog%d passing -c"
                 " example.edu to aklog%d running %s as UID %lu", LOG_DEBUG,
                 LOG_DEBUG, LOG_DEBUG, aklog, (unsigned long) getuid()) < 0)
        sysbail("cannot allocate memory");

    /* Test the various setcred calls that will run aklog. */
    unlink("aklog-args");
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_setcred, 0, argv_cellcomma,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with comma");
    is_aklog_args("-c example.com -c example.edu");
    TEST_PAM(pam_sm_setcred, PAM_REINITIALIZE_CRED, argv_cellcomma,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with comma reinitialize");
    is_aklog_args("-c example.com -c example.edu");
    pam_end(pamh, status);

    /* Test pam_open_session. */
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_open_session, 0, argv_cellcomma,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with comma session");
    is_aklog_args("-c example.com -c example.edu");
    pam_end(pamh, status);

    /* Test with spaces instead of commas. */
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_setcred, 0, argv_cellspace,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with space");
    is_aklog_args("-c example.com -c example.edu");
    pam_end(pamh, status);
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_open_session, 0, argv_cellspace,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with space session");
    is_aklog_args("-c example.com -c example.edu");
    pam_end(pamh, status);

    /* Test with multiple options for the aklog program. */
    free(program);
    if (asprintf(&program, "program=%s,--option,--other-option", aklog) < 0)
        sysbail("cannot allocate memory");
    argv_cellcomma[1] = program;
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_setcred, 0, argv_cellcomma,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with extra args");
    is_aklog_args("--option --other-option -c example.com -c example.edu");
    pam_end(pamh, status);
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_open_session, 0, argv_cellcomma,
             (debug ? passing : ""), PAM_SUCCESS,
             "cells with extra args");
    is_aklog_args("--option --other-option -c example.com -c example.edu");
    pam_end(pamh, status);

    test_file_path_free(aklog);
    free(program);
    free(passing);
}


int
main(void)
{
    if (!k_hasafs())
        skip_all("AFS not available");

    plan(28 * 2);

    run_tests(false);
    run_tests(true);

    return 0;
}
