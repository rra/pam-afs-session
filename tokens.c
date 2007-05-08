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
#include <fcntl.h>
#include <pwd.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_KERBEROS
# include <krb5.h>
#endif

#if HAVE_KAFS_H
# include <kafs.h>
#elif HAVE_KOPENAFS_H
# include <kopenafs.h>
#else
int k_unlog(void);
#endif

/*
 * HP-UX doesn't have a separate environment maintained in the PAM
 * environment, so on that platform just use the regular environment.
 */
#ifndef HAVE_PAM_GETENVLIST
# define pam_getenvlist(p)      (environ)
#endif
#ifndef HAVE_PAM_GETENV
# define pam_getenv(p, e)       getenv(e)
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
        pamafs_debug(args, "ignoring low-UID user (%lu < %d)",
                    (unsigned long) pwd->pw_uid, args->minimum_uid);
        return 1;
    }
    return 0;
}

/*
 * Call aklog with the appropriate environment.  Takes the PAM handle (so that
 * we can get the environment), the arguments, and a struct passwd entry for
 * the user we're authenticating as.  Returns either PAM_SUCCESS or
 * PAM_SESSION_ERR.
 */
static int
pamafs_run_aklog(pam_handle_t *pamh, struct pam_args *args, struct passwd *pwd)
{
    int result;
    char **env;
    pid_t child;

    /* Sanity check that we have some program to run. */
    if (args->program == NULL) {
        pamafs_error("no token program set in PAM arguments");
        return PAM_SESSION_ERR;
    }

    /*
     * Run the program.  Be sure to use _exit instead of exit in the
     * subprocess so that we won't run exit handlers or double-flush stdio
     * buffers in the child process.
     */
    pamafs_debug(args, "running %s as UID %lu", args->program,
                 (unsigned long) pwd->pw_uid);
    env = pam_getenvlist(pamh);
    child = fork();
    if (child < 0) {
        pamafs_error("cannot fork: %s", strerror(errno));
        return PAM_SESSION_ERR;
    } else if (child == 0) {
        if (setuid(pwd->pw_uid) < 0) {
            pamafs_error("cannot setuid to UID %lu: %s",
                         (unsigned long) pwd->pw_uid, strerror(errno));
            _exit(1);
        }
        close(0);
        close(1);
        close(2);
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
        if (args->aklog_homedir) {
            execle(args->program, args->program, "-p", pwd->pw_dir,
                   (char *) 0, env);
        } else {
            execle(args->program, args->program, (char *) 0, env);
        }
        pamafs_error("cannot exec %s: %s", args->program, strerror(errno));
        _exit(1);
    }
    if (waitpid(child, &result, 0) && WIFEXITED(result))
        return PAM_SUCCESS;
    else
        return PAM_SESSION_ERR;
}

/*
 * Call the appropriate krb5_afslog function to get tokens directly without
 * running an external aklog binary.  Returns either PAM_SUCCESS or
 * PAM_SESSION_ERR.
 */
#ifdef HAVE_KRB5_AFSLOG
static int
pamafs_afslog(pam_handle_t *pamh, struct pam_args *args,
              const char *cachename, struct passwd *pwd)
{
    krb5_error_code ret;
    krb5_context ctx;
    krb5_ccache cache;

    if (cachename == NULL) {
        pamafs_debug(args, "skipping tokens, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }
    ret = krb5_init_context(&ctx);
    if (ret != 0) {
        pamafs_error_krb5(NULL, "cannot initialize Kerberos", ret);
        return PAM_SESSION_ERR;
    }
    ret = krb5_cc_resolve(ctx, cachename, &cache);
    if (ret != 0) {
        pamafs_error_krb5(ctx, "cannot open Kerberos ticket cache", ret);
        return PAM_SESSION_ERR;
    }
    if (args->aklog_homedir)
        ret = krb5_afslog_uid_home(ctx, cache, NULL, NULL, pwd->pw_uid,
                                      pwd->pw_dir);
    else
        ret = krb5_afslog_uid(ctx, cache, NULL, NULL, pwd->pw_uid);
    if (ret == 0)
        return PAM_SUCCESS;
    else {
        pamafs_error_krb5(ctx, "cannot obtain tokens", ret);
        return PAM_SESSION_ERR;
    }
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
    krb5_context c;
    krb5_ccache ccache;

    if (!args->kdestroy)
        return;
    ret = krb5_init_context(&c);
    if (ret != 0) {
        pamafs_error_krb5(NULL, "cannot initialize Kerberos", ret);
        return;
    }
    ret = krb5_cc_resolve(c, cache, &ccache);
    if (ret != 0) {
        pamafs_error_krb5(c, "cannot open Kerberos ticket cache", ret);
        return;
    }
    ret = krb5_cc_destroy(c, ccache);
    if (ret != 0)
        pamafs_error_krb5(c, "cannot destroy Kerberos ticket cache", ret);
}
#else /* !HAVE_KERBEROS */
static void
maybe_destroy_cache(struct pam_args *args, const char *cache)
{
    return;
}
#endif /* !HAVE_KERBEROS */

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
    struct passwd *pwd;

    /* Don't try to get a token unless we have a K5 ticket cache. */
    cache = pam_getenv(pamh, "KRB5CCNAME");
    if (cache == NULL && !args->always_aklog) {
        pamafs_debug(args, "skipping tokens, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }

    /* 
     * Get the user, look them up, and see if we should skip this user.  (This
     * will produce warnings on Solaris 8 because pam_get_user is defined to
     * take a char * instead of const char * on that platform, but this should
     * be harmless.)
     */
    status = pam_get_user(pamh, &user, NULL);
    if (status != PAM_SUCCESS || user == NULL) {
        pamafs_error("no user set: %s", pam_strerror(pamh, status));
        return PAM_SESSION_ERR;
    }
    pwd = getpwnam(user);
    if (pwd == NULL) {
        pamafs_error("cannot find UID for %s: %s", user, strerror(errno));
        return PAM_SESSION_ERR;
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
    if (args->program == NULL)
        status = pamafs_afslog(pamh, args, cache, pwd);
    else
        status = pamafs_run_aklog(pamh, args, pwd);
#else
    status = pamafs_run_aklog(pamh, args, pwd);
#endif
    if (status == PAM_SUCCESS) {
        status = pam_set_data(pamh, "pam_afs_session", "yes", NULL);
        if (status != PAM_SUCCESS) {
            pamafs_error("cannot set success data: %s",
                         pam_strerror(pamh, status));
            status = PAM_SESSION_ERR;
        }
        if (status == PAM_SUCCESS)
            maybe_destroy_cache(args, cache);
    } else
        status = PAM_SUCCESS;
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
    const void *dummy;

    /*
     * Do nothing if open_session (or setcred) didn't run.  Otherwise, we may
     * be wiping out some other token that we aren't responsible for.
     */
    if (pam_get_data(pamh, "pam_afs_session", &dummy) != PAM_SUCCESS) {
        pamafs_debug(args, "skipping, no open session");
        return PAM_SUCCESS;
    }

    /* Okay, go ahead and delete the tokens. */
    if (k_unlog() != 0) {
        pamafs_error("unable to delete credentials: %s", strerror(errno));
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}
