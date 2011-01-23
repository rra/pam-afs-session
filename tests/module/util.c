/*
 * Testing utilities for the pam-afs-sesssion module.
 *
 * Provides test functions used by the various test cases for the
 * pam-afs-session module.  Normally, these are called through the macros
 * defined in util.h.
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

#include <syslog.h>

#include <tests/fakepam/testing.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>


/*
 * Checks a PAM call, taking its return status, the expected logging output
 * and exit status, the function name, the flags passed into the call, a
 * boolean to say whether debug will be enabled (which affects the logging
 * output), and a string to use for the test description.
 */
void
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
