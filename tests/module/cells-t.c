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
#include <portable/system.h>

#include <pwd.h>
#include <syslog.h>

#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>


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


int
main(void)
{
    struct script_config config;
    struct passwd *user;
    char *aklog, *uid, *script, *aklog_with_args;
    size_t i, j;
    const char *const session_types[] = {
        "establish", "establish-debug", "reinit", "reinit-debug",
        "open-session", "open-session-debug"
    };
    const char *const session_args_types[] = {
        "establish", "establish-debug", "reinit", "reinit-debug",
        "open-session", "open-session-debug"
    };

    /* Try with both comma- and space-separated options. */
    const char *const afs_cell_options[] = {
        "example.com,example.edu", "example.com , example.edu"
    };

    /* Skip the entire test if AFS isn't available. */
    if (!k_hasafs())
        skip_all("AFS not available");
    plan_lazy();

    /* Configure the path to aklog. */
    memset(&config, 0, sizeof(config));
    aklog = test_file_path("data/fake-aklog");
    config.extra[0] = aklog;
    config.extra[2] = aklog;

    /* Determine the user so that setuid will work. */
    user = getpwuid(getuid());
    if (user == NULL)
        bail("cannot find username of current user");
    pam_set_pwd(user);
    config.user = user->pw_name;
    basprintf(&uid, "%lu", (unsigned long) getuid());
    config.extra[3] = uid;

    /* Fool the module into thinking we have a Kerberos ticket cache. */
    if (putenv((char *) "KRB5CCNAME=krb5cc_test") < 0)
        sysbail("cannot set KRB5CCNAME in the environment");

    /*
     * Run the various tests for both styles of AFS cell configuration, and
     * check that we passed the right thing to the aklog program.
     */
    for (i = 0; i < ARRAY_SIZE(afs_cell_options); i++) {
        config.extra[1] = afs_cell_options[i];
        for (j = 0; j < ARRAY_SIZE(session_types); j++) {
            basprintf(&script, "data/scripts/cells/%s", session_types[j]);
            run_script(script, &config);
            free(script);
            is_aklog_args("-c example.com -c example.edu");
        }
    }

    /* Run a setcred and open_session test with more aklog arguments. */
    basprintf(&aklog_with_args, "%s,--option,--other-option", aklog);
    config.extra[0] = aklog_with_args;
    config.extra[1] = afs_cell_options[0];
    for (i = 0; i < ARRAY_SIZE(session_args_types); i++) {
        basprintf(&script, "data/scripts/cells/%s", session_args_types[i]);
        run_script(script, &config);
        free(script);
        is_aklog_args("--option --other-option -c example.com -c example.edu");
    }

    /* Cleanup. */
    free(aklog_with_args);
    free(uid);
    test_file_path_free(aklog);
    return 0;
}
