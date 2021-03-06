/*
 * Get or delete AFS tokens.
 *
 * Here are the functions to get or delete AFS tokens, called by the various
 * public functions.  The functions to get tokens should run after a PAG is
 * created.  All functions here assume that AFS is running and k_hasafs() has
 * already been called.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#ifdef HAVE_KERBEROS
# include <portable/krb5.h>
#endif
#include <portable/pam.h>
#include <portable/system.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>
#include <pam-util/vector.h>

/*
 * HP-UX doesn't have a separate environment maintained in the PAM
 * environment, so on that platform just use the regular environment.
 */
#ifndef HAVE_PAM_GETENVLIST
# define pam_getenvlist(p)      (environ)
# define pamafs_free_envlist(e) /* empty */
#endif
#ifndef HAVE_PAM_GETENV
# define pam_getenv(p, e)       getenv(e)
#endif


/*
 * Free the results of pam_getenvlist, but only if we have pam_getenvlist.
 */
#ifdef HAVE_PAM_GETENVLIST
static void
pamafs_free_envlist(char **env)
{
    size_t i;

    for (i = 0; env[i] != NULL; i++)
        free(env[i]);
    free(env);
}
#endif


/*
 * Given the PAM arguments and the passwd struct of the user we're
 * authenticating, see if we should ignore that user because they're root or
 * have a low-numbered UID and we were configured to ignore such users.
 * Returns true if we should ignore them, false otherwise.
 */
static bool
pamafs_should_ignore(struct pam_args *args, const struct passwd *pwd)
{
    long minimum_uid = args->config->minimum_uid;

    if (args->config->ignore_root && strcmp("root", pwd->pw_name) == 0) {
        putil_debug(args, "ignoring root user");
        return true;
    }
    if (minimum_uid > 0 && pwd->pw_uid < (unsigned long) minimum_uid) {
        putil_debug(args, "ignoring low-UID user (%lu < %ld)",
                    (unsigned long) pwd->pw_uid, minimum_uid);
        return true;
    }
    return false;
}


/*
 * Build the environment for running aklog.  There is some complexity here to
 * handle the case where KRB5CCNAME is set in the general environment but not
 * in the PAM environment.  In that case, we lift it into the environment that
 * we pass into aklog.
 *
 * Returns the environment on success and NULL on failure.  The caller is
 * responsible for freeing the environment and all memory it points to.
 */
static char **
pamafs_build_env(struct pam_args *args)
{
    char **env;
    const char *cache;
    size_t i;

    env = pam_getenvlist(args->pamh);
    if (env == NULL)
        return NULL;

    /*
     * Check whether KRB5CCNAME is set in the PAM environment.  If it isn't,
     * but it is set in the regular environment, we're going to have to add it
     * into the environment passed to aklog.
     */
    cache = pam_getenv(args->pamh, "KRB5CCNAME");
    if (cache == NULL)
        cache = getenv("KRB5CCNAME");
    else
        cache = NULL;
    if (cache != NULL) {
        for (i = 0; env[i] != NULL; i++)
            ;
        env = realloc(env, sizeof(char **) * (i + 2));
        env[i] = NULL;
        env[i + 1] = NULL;
        if (env == NULL)
            return NULL;
        if (asprintf(&env[i], "KRB5CCNAME=%s", cache) < 0) {
            env[i] = NULL;
            return NULL;
        }
    }
    return env;
}

/*
 * Call aklog with the appropriate environment.  Takes the PAM handle (so that
 * we can get the environment), the arguments, and a struct passwd entry for
 * the user we're authenticating as.  Returns either PAM_SUCCESS or
 * PAM_CRED_ERR.
 */
static int
pamafs_run_aklog(struct pam_args *args, struct passwd *pwd)
{
    int res, status;
    size_t i;
    char **env = NULL;
    struct vector *argv = NULL;
    struct sigaction sa, oldsa;
    bool restore_handler = false;
    pid_t child;

    /* Sanity check that we have some program to run. */
    if (args->config->program == NULL) {
        putil_err(args, "no token program set in PAM arguments");
        return PAM_CRED_ERR;
    }

    /* Build the options for the program. */
    argv = vector_copy(args->config->program);
    if (argv == NULL)
        goto memfail;
    if (args->config->aklog_homedir) {
        if (!vector_add(argv, "-p") || !vector_add(argv, pwd->pw_dir))
            goto memfail;
        putil_debug(args, "passing -p %s to aklog", pwd->pw_dir);
    }
    if (args->config->afs_cells != NULL)
        for (i = 0; i < args->config->afs_cells->count; i++) {
            if (!vector_add(argv, "-c"))
                goto memfail;
            if (!vector_add(argv, args->config->afs_cells->strings[i]))
                goto memfail;
            putil_debug(args, "passing -c %s to aklog",
                        args->config->afs_cells->strings[i]);
        }

    /*
     * The application that calls us may have set a SIGCHLD handler, but we
     * need to ensure that's not called for aklog, so we temporarily override
     * it.  This is a bit of a disaster if the application has other children
     * that it wants to handle while we run aklog; there seems to be no good
     * solution here.
     */
    memset(&sa, 0, sizeof(sa));
    memset(&oldsa, 0, sizeof(oldsa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &sa, &oldsa) < 0)
        putil_err(args, "cannot set SIGCHLD handler, continuing anyway");
    else
        restore_handler = true;

    /*
     * Run the program.  Be sure to use _exit instead of exit in the
     * subprocess so that we won't run exit handlers or double-flush stdio
     * buffers in the child process.
     */
    env = pamafs_build_env(args);
    putil_debug(args, "running %s as UID %lu",
                args->config->program->strings[0],
                (unsigned long) pwd->pw_uid);
    child = fork();
    if (child < 0) {
        putil_crit(args, "cannot fork: %s", strerror(errno));
        goto fail;
    } else if (child == 0) {
        if (setuid(pwd->pw_uid) < 0) {
            putil_crit(args, "cannot setuid to UID %lu: %s",
                       (unsigned long) pwd->pw_uid, strerror(errno));
            _exit(1);
        }
        close(0);
        close(1);
        close(2);
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
        vector_exec_env(args->config->program->strings[0], argv,
                        (const char * const *) env);
        putil_err(args, "cannot exec %s: %s",
                  args->config->program->strings[0], strerror(errno));
        _exit(1);
    }
    vector_free(argv);
    argv = NULL;
    pamafs_free_envlist(env);
    if (waitpid(child, &res, 0) && WIFEXITED(res) && WEXITSTATUS(res) == 0)
        status = PAM_SUCCESS;
    else {
        putil_err(args, "aklog program %s returned %d",
                  args->config->program->strings[0], WEXITSTATUS(res));
        status = PAM_CRED_ERR;
    }
    if (restore_handler)
        if (sigaction(SIGCHLD, &oldsa, NULL) < 0)
            putil_err(args, "cannot restore SIGCHLD handler");
    return status;

memfail:
    putil_crit(args, "cannot allocate memory: %s", strerror(errno));
fail:
    if (argv != NULL)
        vector_free(argv);
    if (env != NULL)
        pamafs_free_envlist(env);
    if (restore_handler)
        if (sigaction(SIGCHLD, &oldsa, NULL) < 0)
            putil_err(args, "cannot restore SIGCHLD handler");
    return PAM_CRED_ERR;
}


/*
 * Call the appropriate krb5_afslog function to get tokens directly without
 * running an external aklog binary.  Returns either PAM_SUCCESS or
 * PAM_CRED_ERR.
 */
#ifdef HAVE_KRB5_AFSLOG
static int
pamafs_afslog(struct pam_args *args, const char *cachename,
              struct passwd *pwd)
{
    krb5_error_code ret;
    krb5_ccache cache;
    size_t i;

    if (cachename == NULL) {
        putil_debug(args, "skipping tokens, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }
    ret = krb5_cc_resolve(args->ctx, cachename, &cache);
    if (ret != 0) {
        putil_err_krb5(args, ret, "cannot open Kerberos ticket cache");
        return PAM_CRED_ERR;
    }
    if (args->config->aklog_homedir) {
        putil_debug(args, "obtaining tokens for UID %lu and directory %s",
                    (unsigned long) pwd->pw_uid, pwd->pw_dir);
        ret = krb5_afslog_uid_home(args->ctx, cache, NULL, NULL, pwd->pw_uid,
                                   pwd->pw_dir);
        if (ret != 0)
            putil_err_krb5(args, ret, "cannot obtain tokens for path %s",
                           pwd->pw_dir);
    } else if (args->config->afs_cells == NULL) {
        putil_debug(args, "obtaining tokens for UID %lu",
                    (unsigned long) pwd->pw_uid);
        ret = krb5_afslog_uid(args->ctx, cache, NULL, NULL, pwd->pw_uid);
        if (ret != 0)
            putil_err_krb5(args, ret, "cannot obtain tokens");
    } else {
        for (i = 0; i < args->config->afs_cells->count; i++) {
            int status;

            putil_debug(args, "obtaining tokens for UID %lu in cell %s",
                        (unsigned long) pwd->pw_uid,
                        args->config->afs_cells->strings[i]);
            status = krb5_afslog_uid(args->ctx, cache,
                                     args->config->afs_cells->strings[i],
                                     NULL, pwd->pw_uid);
            if (status != 0) {
                putil_err_krb5(args, ret, "cannot obtain tokens for cell %s",
                               args->config->afs_cells->strings[i]);
                if (ret == 0)
                    ret = status;
            }
        }
    }
    krb5_cc_close(args->ctx, cache);
    if (ret == 0)
        return PAM_SUCCESS;
    else
        return PAM_CRED_ERR;
}
#endif


/*
 * If the kdestroy option is set and we were built with Kerberos support,
 * destroy the ticket cache after we successfully got tokens.
 */
#ifdef HAVE_KERBEROS
static void
maybe_destroy_cache(struct pam_args *args, const char *cache)
{
    krb5_error_code ret;
    krb5_ccache ccache;

    if (!args->config->kdestroy)
        return;
    ret = krb5_cc_resolve(args->ctx, cache, &ccache);
    if (ret != 0) {
        putil_err_krb5(args, ret, "cannot open Kerberos ticket cache");
        return;
    }
    putil_debug(args, "destroying ticket cache");
    ret = krb5_cc_destroy(args->ctx, ccache);
    if (ret != 0)
        putil_err_krb5(args, ret, "cannot destroy Kerberos ticket cache");
}
#else /* !HAVE_KERBEROS */
static void
maybe_destroy_cache(struct pam_args *args UNUSED, const char *cache UNUSED)
{
    return;
}
#endif /* !HAVE_KERBEROS */


/*
 * Obtain AFS tokens.  Does various sanity checks first, ensuring that we have
 * a Kerberos ticket cache, that we can resolve the username, and that we're
 * not supposed to ignore this user.
 *
 * Normally, set our flag data item if tokens were successfully obtained.
 * This prevents a subsequent setcred or open_session from doing anything and
 * flags close_session to remove the token.  However, don't do this if the
 * reinitialize flag is set, since in that case we're refreshing a token we're
 * not subsequently responsible for.  This fixes problems with sudo when it
 * has pam_setcred enabled, since it calls pam_setcred with
 * PAM_REINITIALIZE_CRED first before calling pam_open_session, and we don't
 * want to skip the pam_open_session or PAG creation or remove the credentials
 * created in pam_setcred outside of the new session.
 *
 * Returns error codes for pam_setcred, since those are the most granular.  A
 * caller implementing pam_open_session needs to map these (generally by
 * mapping all failures to PAM_SESSION_ERR).
 */
int
pamafs_token_get(struct pam_args *args, bool reinitialize)
{
    int status;
    PAM_CONST char *user;
    const char *cache;
    struct passwd *pwd;

    /* Don't try to get a token unless we have a K5 ticket cache. */
    cache = pam_getenv(args->pamh, "KRB5CCNAME");
    if (cache == NULL)
        cache = getenv("KRB5CCNAME");
    if (cache == NULL && !args->config->always_aklog) {
        putil_debug(args, "skipping tokens, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }

    /* Get the user, look them up, and see if we should skip this user. */
    status = pam_get_user(args->pamh, &user, NULL);
    if (status != PAM_SUCCESS || user == NULL) {
        putil_err_pam(args, status, "no user set");
        return PAM_USER_UNKNOWN;
    }
    pwd = pam_modutil_getpwnam(args->pamh, user);
    if (pwd == NULL) {
        putil_err(args, "cannot find UID for %s: %s", user, strerror(errno));
        return PAM_USER_UNKNOWN;
    }
    if (pamafs_should_ignore(args, pwd))
        return PAM_SUCCESS;

    /*
     * If we have krb5_afslog and no program was specifically set, call it.
     * Otherwise, run aklog.
     *
     * Always return success even if obtaining tokens failed.  An argument
     * could be made for failing if getting tokens fails, but that may cause
     * the user to be kicked out of their session when their home directory
     * may not even be in AFS.  Continuing without tokens should at worst
     * result in errors of being unable to access their home directory; this
     * isn't the authentication module and isn't responsible for ensuring the
     * user should have access.
     *
     * This could be made an option later if necessary, but I'd rather avoid
     * too many options.
     */
#ifdef HAVE_KRB5_AFSLOG
    if (args->config->program == NULL)
        status = pamafs_afslog(args, cache, pwd);
    else
        status = pamafs_run_aklog(args, pwd);
#else
    status = pamafs_run_aklog(args, pwd);
#endif
    if (status == PAM_SUCCESS && !reinitialize) {
        status = pam_set_data(args->pamh, "pam_afs_session", (char *) "yes",
                              NULL);
        if (status != PAM_SUCCESS) {
            putil_err_pam(args, status, "cannot set success data");
            status = PAM_CRED_ERR;
        }
    }
    if (status == PAM_SUCCESS)
        maybe_destroy_cache(args, cache);
    return PAM_SUCCESS;
}


/*
 * Delete AFS tokens by running k_unlog, but only if our flag data item was
 * set indicating that we'd previously gotten AFS tokens.  Returns either
 * PAM_SUCCESS or PAM_SESSION_ERR.
 */
int
pamafs_token_delete(struct pam_args *args)
{
    const void *dummy;
    int status;

    /*
     * Do nothing if open_session (or setcred) didn't run.  Otherwise, we may
     * be wiping out some other token that we aren't responsible for.
     */
    if (pam_get_data(args->pamh, "pam_afs_session", &dummy) != PAM_SUCCESS) {
        putil_debug(args, "skipping, no open session");
        return PAM_SUCCESS;
    }

    /* Okay, go ahead and delete the tokens. */
    putil_debug(args, "destroying tokens");
    if (k_unlog() != 0) {
        putil_err(args, "unable to delete credentials: %s", strerror(errno));
        return PAM_SESSION_ERR;
    }

    /*
     * Remove our module data, just in case someone wants to create a new
     * session again later inside the same PAM session.  Just complain but
     * don't fail if we can't delete it, since this is unlikely to cause any
     * significant problems.
     */
    status = pam_set_data(args->pamh, "pam_afs_session", NULL, NULL);
    if (status != PAM_SUCCESS)
        putil_err_pam(args, status, "unable to remove module data");

    return PAM_SUCCESS;
}
