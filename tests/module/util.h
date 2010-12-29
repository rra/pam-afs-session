/*
 * Testing utilities for the pam-afs-session module.
 *
 * This header provides macros and prototypes for utility functions for
 * testing the pam-afs-session module.  It takes care of setting up the
 * infrastructure to make it easy to call entry points of the module and check
 * the results and logged output.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TESTS_MODULE_UTIL_H
#define TESTS_MODULE_UTIL_H 1

#include <config.h>
#include <portable/macros.h>

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
 *
 * pamh (the PAM handle), debug (a boolean saying whether debug is enabled),
 * and debug_desc (a string to append saying whether debug is enabled for the
 * test description) must be provided in the caller's context.
 */
#define TEST_PAM(m, f, a, o, s, d)                                      \
    do {                                                                \
        is_pam_call((o), (s), m(pamh, (f), ARGV(a)), #m, (f), debug,    \
                    #m " %s%s", (d), debug_desc);                       \
    } while (0)

BEGIN_DECLS

/*
 * Checks a PAM call, taking its return status, the expected logging output
 * and exit status, the function name, the flags passed into the call, a
 * boolean to say whether debug will be enabled (which affects the logging
 * output), and a string to use for the test description.
 */
void is_pam_call(const char *output, int expected, int seen,
                 const char *function, int flags, bool debug,
                 const char *format, ...);

END_DECLS

#endif /* !TESTS_MODULE_UTIL_H */
