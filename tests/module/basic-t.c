/*
 * Basic tests for the pam-afs-session module.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <syslog.h>

#include <kafs/kafs.h>
#include <tests/fakepam/api.h>
#include <tests/fakepam/testing.h>
#include <tests/tap/basic.h>

#define ARRAY_SIZEOF(a) (sizeof(a) / sizeof((a)[0]))


int
main(void)
{
    pam_handle_t *pamh;
    int status;
    char *output, *expected;
    const char *argv_nothing[] = { "nopag", "notokens", NULL };
    const char *argv_nothing_debug[] = { "nopag", "notokens", "debug", NULL };

    plan(4);

    /* Do nothing and check for correct output status. */
    status = pam_start("test", "testuser", NULL, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    status = pam_sm_open_session(pamh, 0, ARRAY_SIZEOF(argv_nothing) - 1,
                                 argv_nothing);
    output = pam_output();
    if (!k_hasafs()) {
        is_int(status, PAM_IGNORE, "session status, no AFS");
        asprintf(&expected, "%d pam_sm_open_session: entry (0x0)", LOG_ERR);
        is_string(expected, output, "session output, no AFS");
        free(expected);
    } else {
        is_int(status, PAM_SUCCESS, "session status, do nothing");
        is_string(NULL, output, "session output, do nothing");
    }
    free(output);
    pam_end(pamh, status);

    /* Do nothing with debug enabled and check for correct output status. */
    status = pam_start("test", "testuser", NULL, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    status = pam_sm_open_session(pamh, 0, ARRAY_SIZEOF(argv_nothing_debug) - 1,
                                 argv_nothing_debug);
    output = pam_output();
    if (!k_hasafs()) {
        is_int(status, PAM_IGNORE, "session status w/debug, no AFS");
        asprintf(&expected, "%d pam_sm_open_session: entry (0x0)"
                 "%d skipping, AFS apparently not available"
                 "%d pam_sm_open_session: exit (ignore)", LOG_DEBUG,
                 LOG_ERR, LOG_DEBUG);
        is_string(expected, output, "session output w/debug, no AFS");
        free(expected);
    } else {
        is_int(status, PAM_SUCCESS, "session status w/debug, do nothing");
        asprintf(&expected, "%d pam_sm_open_session: entry (0x0)"
                 "%d pam_sm_open_session: exit (success)", LOG_DEBUG,
                 LOG_DEBUG);
        is_string(expected, output, "session output w/debug, do nothing");
        free(expected);
    }
    free(output);
    pam_end(pamh, status);

    return 0;
}
