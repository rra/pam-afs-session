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

#include <tests/fakepam/pam.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>


/*
 * If we don't have AFS, the status will depend on which function we call.
 * This function returns either PAM_SUCCESS or PAM_IGNORE based on the
 * function, reflecting the expected error message from AFS being
 * unavailable.
 */
static int
no_afs_status(const char *function)
{
    if (strcmp("pam_sm_authenticate", function) == 0)
        return PAM_SUCCESS;
    else if (strcmp("pam_sm_setcred", function) == 0)
        return PAM_SUCCESS;
    else
        return PAM_IGNORE;
}


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
    struct output *lines;
    size_t i;
    char *desc, *next;
    char *logs = NULL;
    char *p = NULL;
    va_list args;
    int status;

    va_start(args, format);
    if (vasprintf(&desc, format, args) < 0)
        sysbail("cannot allocate memory");
    va_end(args);
    lines = pam_output();
    if (lines != NULL) {
        for (i = 0; i < lines->count; i++) {
            if (logs == NULL)
                basprintf(&logs, "%d %s", lines->lines[i].priority,
                          lines->lines[i].line);
            else {
                basprintf(&next, "%s%d %s", logs, lines->lines[i].priority,
                          lines->lines[i].line);
                free(logs);
                logs = next;
            }
        }
        pam_output_free(lines);
    }
    if (!k_hasafs()) {
        status = no_afs_status(function);
        is_int(status, seen, "%s (status)", desc);
        if (strcmp(function, "pam_sm_authenticate") == 0) {
            /* Leave p as NULL, no output expected. */
        } else if (debug) {
            if (asprintf(&p, "%d %s: entry (0x%x)"
                         "%d skipping, AFS apparently not available"
                         "%d %s: exit (%s)", LOG_DEBUG, function,
                         flags, LOG_ERR, LOG_DEBUG, function,
                         status == PAM_IGNORE ? "ignore" : "success") < 0)
                sysbail("cannot allocate memory");
        } else {
            if (asprintf(&p, "%d skipping, AFS apparently not available",
                         LOG_ERR) < 0)
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
