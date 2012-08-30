/*
 * Test SIGCHLD handling and not leaking to parent signal handler.
 *
 * Ensure that if our calling process has its own SIGCHLD handler, that
 * handler isn't triggered by the fork of aklog.  This is ugly in
 * multithreaded processes and may not be quite the right solution still.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <signal.h>
#include <pwd.h>
#include <syslog.h>

#include <internal.h>
#include <tests/fakepam/pam.h>
#include <tests/module/util.h>
#include <tests/tap/basic.h>

/* The signal flag set if the wrong SIGCHLD handler is called. */
static volatile sig_atomic_t child_signaled = 0;


/*
 * Signal handler in parent, which sets child_signaled.  This should never be
 * called if the module is working properly.
 */
static void
child_handler(int sig UNUSED)
{
    child_signaled = 1;
}


int
main(void)
{
    pam_handle_t *pamh;
    struct sigaction sa;
    int status;
    char *aklog = test_file_path ("data/fake-aklog");
    char *program, *running;
    struct passwd *user;
    struct pam_conv conv = { NULL, NULL };
    const char *argv[] = { "program=", "always_aklog", "nopag", NULL };
    bool debug = false;
    const char *debug_desc = "";

    plan(4);

    /* Set up the SIGCHLD handler. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = child_handler;
    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        sysbail("cannot set SIGCHLD handler");

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");

    /* Build some messages that we'll use multiple times. */
    if (asprintf(&program, "program=%s", aklog) < 0)
        sysbail("cannot allocate memory");
    argv[0] = program;
    if (asprintf(&running, "%d running %s as UID %lu", LOG_DEBUG, aklog,
                 (unsigned long) getuid()) < 0)
        sysbail("cannot allocate memory");

    /* Run the session setup and ensure our child handler isn't called. */
    unlink("aklog-args");
    status = pam_start("test", user->pw_name, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (pam_putenv(pamh, "KRB5CCNAME=krb5cc_test") != PAM_SUCCESS)
        sysbail("cannot set PAM environment variable");
    TEST_PAM(pam_sm_setcred, 0, argv, (debug ? running : ""),
             PAM_SUCCESS, "normal");
    ok(access("aklog-args", F_OK) == 0, "aklog was run");
    is_int(0, child_signaled, "...and SIGCHLD handler not run");
    unlink("aklog-args");
    pam_end(pamh, status);

    test_file_path_free(aklog);
    free(program);
    free(running);

    return 0;
}
