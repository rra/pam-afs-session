/*
 * PAM logging test suite.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/stdbool.h>
#include <portable/system.h>

#include <syslog.h>

#include <tests/fakepam/api.h>
#include <tests/fakepam/testing.h>
#include <tests/tap/basic.h>

#define TESTING 1
#include <pam-util/args.h>
#include <pam-util/logging.h>

/* Test a normal PAM logging function. */
#define TEST(func, p, n)                              \
    do {                                              \
        (func)(args, "%s", "foo");                    \
        asprintf(&expected, "%d %s", (p), "foo");     \
        seen = pam_output();                          \
        is_string(expected, seen, "%s", (n));         \
        free(seen);                                   \
        free(expected);                               \
    } while(0);


int
main(void)
{
    pam_handle_t *pamh;
    struct pam_args *args;
    char *expected, *seen;

    plan(4);

    if (pam_start(NULL, NULL, NULL, &pamh) != PAM_SUCCESS)
        sysbail("Fake PAM initialization failed");
    args = putil_args_new(pamh);
    TEST(putil_crit,  LOG_CRIT,  "putil_crit");
    TEST(putil_err,   LOG_ERR,   "putil_err");
    putil_debug(args, "%s", "foo");
    ok(pam_output() == NULL, "putil_debug without debug on");
    args->debug = true;
    TEST(putil_debug, LOG_DEBUG, "putil_debug");

    return 0;
}
