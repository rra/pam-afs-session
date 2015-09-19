/*
 * Test SIGCHLD handling and not leaking to parent signal handler.
 *
 * Ensure that if our calling process has its own SIGCHLD handler, that
 * handler isn't triggered by the fork of aklog.  This is ugly in
 * multithreaded processes and may not be quite the right solution still.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2015 Russ Allbery <eagle@eyrie.org>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <signal.h>
#include <pwd.h>

#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
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
    struct sigaction sa;
    struct script_config config;
    struct passwd *user;
    char *aklog;

    /* Set up the plan. */
    plan_lazy();

    /* Set up the SIGCHLD handler. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = child_handler;
    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        sysbail("cannot set SIGCHLD handler");

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);

    /* Configure the path to aklog. */
    memset(&config, 0, sizeof(config));
    aklog = test_file_path("data/fake-aklog");
    config.user = user->pw_name;
    config.extra[0] = aklog;

    /* Fool the module into thinking we have a Kerberos ticket cache. */
    if (putenv((char *) "KRB5CCNAME=krb5cc_test") < 0)
        sysbail("cannot set KRB5CCNAME in the environment");

    /* Run the PAM module and ensure our child handler isn't called. */
    unlink("aklog-args");
    run_script("data/scripts/sigchld/establish", &config);
    ok(access("aklog-args", F_OK) == 0, "aklog was run");
    is_int(0, child_signaled, "...and SIGCHLD handler not run");
    unlink("aklog-args");

    /* Clean up. */
    test_file_path_free(aklog);
    return 0;
}
