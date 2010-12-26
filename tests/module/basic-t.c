/*
 * Basic tests for the pam-afs-session module.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <syslog.h>

#include <kafs/kafs.h>
#include <tests/fakepam/testing.h>
#include <tests/tap/basic.h>

/*
 * These macros implement a bit of sneakiness.  For all of our argv strings,
 * debug is the last argument.  Based on the debug variable setting, choose
 * whether to include that argument or not.
 */
#define ARRAY_SIZEOF(a) (sizeof(a) / sizeof((a)[0]))
#define ARGV(a) ARRAY_SIZEOF(a) - (debug ? 1 : 2), (a)


/*
 * Make a call to a PAM module function and then check it with is_pam_call.
 * Takes the PAM method, the flags, the argv to use, the expected output, the
 * expected status, and a string description.
 */
#define TEST_PAM(m, f, a, o, s, d)                                      \
    do {                                                                \
        is_pam_call((o), (s), m(pamh, (f), ARGV(a)), #m, (f), debug,    \
                    #m " %s%s", (d), debug_desc);                       \
    } while (0)


/*
 * Checks a PAM call, taking its return status, the expected logging output
 * and exit status, the function name, the flags passed into the call, a
 * boolean to say whether debug will be enabled (which affects the logging
 * output), and a string to use for the test description.
 */
static void
is_pam_call(const char *output, int expected, int seen, const char *function,
            int flags, bool debug, const char *format, ...)
{
    char *logs, *desc;
    char *p = NULL;
    va_list args;

    va_start(args, format);
    if (vasprintf(&desc, format, args) < 0)
        sysbail("cannot allocate memory");
    va_end(args);
    logs = pam_output();
    if (!k_hasafs()) {
        is_int(PAM_IGNORE, seen, "%s (status)", desc);
        if (debug && strcmp(function, "pam_sm_authenticate") != 0) {
            if (asprintf(&p, "%d %s: entry (0x%x)"
                         "%d skipping, AFS apparently not available"
                         "%d %s: exit (ignore)", LOG_DEBUG, function,
                         flags, LOG_ERR, LOG_DEBUG, function) < 0)
                sysbail("cannot allocate memory");
        }
        is_string(p, logs, "%s (output)", desc);
        if (p != NULL)
            free(p);
    } else {
        is_int(expected, seen, "%s (status)", desc);
        if (debug && strcmp(function, "pam_sm_authenticate") != 0) {
            if (asprintf(&p, "%d %s: entry (0x%x)%s%d %s: exit (%s)",
                         LOG_DEBUG, function, flags, output, LOG_DEBUG,
                         function, ((expected == PAM_SUCCESS) ? "success"
                                    : (expected == PAM_IGNORE) ? "ignore"
                                    : "failure")) < 0)
                sysbail("cannot allocate memory");
            is_string(p, logs, "%s (output)", desc);
        } else {
            if (output != NULL && output[0] == '\0')
                is_string(NULL, logs, "%s (output)", desc);
            else
                is_string(output, logs, "%s (output)", desc);
        }
        if (p != NULL)
            free(p);
    }
    if (logs != NULL)
        free(logs);
    free(desc);
}


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
    const char *argv_nothing[] = { "nopag", "notokens", "debug", NULL };

    /* Build some messages that we'll use multiple times. */
    if (asprintf(&skipping, "%d skipping as configured", LOG_DEBUG) < 0)
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
