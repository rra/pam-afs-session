/*
 * Basic tests for the pam-afs-session module.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#include <portable/system.h>

#include <errno.h>
#include <pwd.h>

#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>


int
main(void)
{
    struct script_config config;
    struct passwd *user;
    char *aklog, *uid, *script;
    size_t i;
    const char *const session_types[] = {
        "establish", "establish-debug", "refresh", "refresh-debug",
        "reinit", "reinit-debug", "open-session", "open-session-debug"
    };

    /* Skip the entire test if AFS isn't available. */
    if (!k_hasafs())
        skip_all("AFS not available");
    plan_lazy();

    /*
     * Clear KRB5CCNAME out of the environment to avoid running aklog when we
     * don't expect to.
     */
    if (putenv((char *) "KRB5CCNAME") < 0)
        sysbail("cannot clear KRB5CCNAME from the environment");

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);

    /* Configure the path to aklog. */
    memset(&config, 0, sizeof(config));
    aklog = test_file_path("data/fake-aklog");
    config.extra[0] = aklog;

    /* Initial no-op tests. */
    config.user = "testuser";
    run_script("data/scripts/basic/noop", &config);
    run_script("data/scripts/basic/noop-debug", &config);

    /*
     * Test behavior without a Kerberos ticket.  This doesn't test actual
     * creation of a PAG.
     */
    unlink("aklog-args");
    run_script("data/scripts/basic/no-ticket", &config);
    run_script("data/scripts/basic/no-ticket-debug", &config);
    ok(access("aklog-args", F_OK) < 0, "aklog was not run");

    /*
     * Remaining tests run with the module fooled into thinking we have a
     * Kerberos ticket cache.
     */
    if (putenv((char *) "KRB5CCNAME=krb5cc_test") < 0)
        sysbail("cannot set KRB5CCNAME in the environment");

    /* Unknown user.  Be sure to get the strerror message. */
    config.user = "pam-afs-session-unknown-user";
    config.extra[1] = strerror(0);
    run_script("data/scripts/basic/unknown", &config);
    run_script("data/scripts/basic/unknown-debug", &config);
    config.extra[1] = NULL;

    /* Check that aklog runs in various ways of opening a session. */
    config.user = user->pw_name;
    basprintf(&uid, "%lu", (unsigned long) getuid());
    config.extra[1] = uid;
    for (i = 0; i < ARRAY_SIZE(session_types); i++) {
        unlink("aklog-args");
        basprintf(&script, "data/scripts/basic/%s", session_types[i]);
        run_script(script, &config);
        free(script);
        ok(access("aklog-args", F_OK) == 0, "aklog was run");
    }
    unlink("aklog-args");
    config.extra[1] = NULL;
    free(uid);

    /* Clean up. */
    test_file_path_free(aklog);
    return 0;
}
