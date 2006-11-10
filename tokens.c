/*
 * tokens.c
 *
 * Get or delete AFS tokens.
 *
 * Here are the functions to get or delete AFS tokens, called by the various
 * public functions.  The functions to get tokens should run after a PAG is
 * created.  All functions here assume that AFS is running and k_hasafs() has
 * already been called.
 */

#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_KAFS_H
# include <kafs.h>
#elif
# include <kopenafs.h>
#else
int k_unlog(void);
#endif

#include "internal.h"

/*
 * Given the PAM arguments and the passwd struct of the user we're
 * authenticating, see if we should ignore that user because they're root or
 * have a low-numbered UID and we were configured to ignore such users.
 * Returns true if we should ignore them, false otherwise.
 */
static int
pamafs_should_ignore(struct pam_args *args, const struct passwd *pwd)
{
    if (args->ignore_root && strcmp("root", pwd->pw_name) == 0) {
        pamafs_debug(args, "ignoring root user");
        return 1;
    }
    if (args->minimum_uid > 0 && pwd->pw_uid < args->minimum_uid) {
        pamk5_debug(ctx, args, "ignoring low-UID user (%lu < %d)",
                    (unsigned long) pwd->pw_uid, args->minimum_uid);
            return 1;
        }
    }
    return 0;
}

/*
 * Call aklog with the appropriate environment.  Takes the PAM handle (so that
 * we can get the environment), the path to aklog, and the path to the ticket
 * cache (possibly a template).  Returns either PAM_SUCCESS or
 * PAM_SESSION_ERR.
 */
static int
pamafs_run_aklog(struct pam_args *args, uid_t uid)
{
    int status, result;
    char **env;
    pid_t child;

    pamafs_debug(args, "running %s as UID %lu", args->program,
                 (unsigned long) uid);
    env = pam_getenvlist(pamh);
    child = fork();
    if (child < 0)
        return PAM_SESSION_ERR;
    else if (child == 0) {
        if (setuid(pwd->pw_uid) < 0) {
            pamafs_error("cannot setuid to UID %lu: %s",
                         (unsigned long) uid, strerror(errno));
            _exit(1);
        }
        execle(args->program, args->program, NULL, env);
        pamafs_error("cannot exec %s: %s", args->program, strerror(errno));
        _exit(1);
    }
    if (waitpid(child, &result, 0) && WIFEXITED(result))
        return PAM_SUCCESS;
    else
        return PAM_SESSION_ERR;
}

/*
 * Obtain AFS tokens, currently always by running aklog but eventually via the
 * kafs interface as well.  Does various sanity checks first, ensuring that we
 * have a K5 ticket cache, that we can resolve the username, and that we're
 * not supposed to ignore this user.  Sets our flag data item if tokens were
 * successfully obtained.  Returns either PAM_SUCCESS or PAM_SESSION_ERR.
 */
int
pamafs_token_get(pam_handle_t *pamh, struct pam_args *args)
{
    int status;
    const char *user, *cache;
    const void *dummy;
    struct passwd *pwd;

    /* Don't try to get a token unless we have a K5 ticket cache. */
    cache = pam_getenv(pamh, "KRB5CCNAME");
    if (cache == NULL) {
        pamafs_debug("skipping, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }

    /* Get the user, look them up, and see if we should skip this user. */
    status = pam_get_user(pamh, &user, NULL);
    if (status != PAM_SUCCESS || user == NULL) {
        pamafs_error("no user set: %s", pam_strerror(status));
        return PAM_SESSION_ERR;
    }
    pwd = getpwnam(user);
    if (pwd == NULL) {
        pamafs_error("cannot find UID for %s: %s", user, strerror(errno));
        return PAM_SESSION_ERR;
    }
    if (pamafs_should_ignore(args, pwd))
        return PAM_SUCCESS;
    status = pamafs_run_aklog(args, pwd->pw_uid);
    if (status == PAM_SUCCESS) {
        status = pam_set_data(pamh, "pam_afs_session", "yes", NULL);
        if (status != PAM_SUCCESS) {
            pamafs_error("cannot set success data: %s", pam_strerror(status));
            status = PAM_SESSION_ERR;
        }
    } else
        status = PAM_SESSION_ERR;
    return status;
}

/*
 * Delete AFS tokens by running k_unlog, but only if our flag data item was
 * set indicating that we'd previously gotten AFS tokens.  Returns either
 * PAM_SUCCESS or PAM_SESSION_ERR.
 */
int
pamafs_token_delete(pam_handle_t *pamh, struct pam_args *args)
{
    int pamret;

    /*
     * Do nothing if open_session (or setcred) didn't run.  Otherwise, we may
     * be wiping out some other token that we aren't responsible for.
     */
    status = pam_get_data(pamh, "pam_afs_session", &dummy);
    if (status != PAM_SUCCESS) {
        pamafs_debug("skipping, no open session");
        return PAM_SUCCESS;
    }

    /* Okay, go ahead and delete the tokens. */
    if (k_unlog() != 0) {
        pamafs_error("unable to delete credentials: %s", strerror(errno));
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}
