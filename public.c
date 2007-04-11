/*
 * public.c
 *
 * The public APIs of the pam_afs_session PAM module.
 *
 * Provides the public pam_sm_setcred, pam_sm_open_session, and
 * pam_sm_close_session functions, plus whatever other stubs we need to
 * satisfy PAM.
 */

#include "config.h"

#include <errno.h>
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
#include <unistd.h>

#if HAVE_KAFS_H
# include <kafs.h>
#elif HAVE_KOPENAFS_H
# include <kopenafs.h>
#else
int k_hasafs(void);
int k_setpag(void);
#endif

#include "internal.h"

/*
 * Open a new session.  Create a new PAG with k_setpag and then fork the aklog
 * binary as the user.  A Kerberos v5 PAM module should have previously run to
 * obtain Kerberos tickets (or ticket forwarding should have already
 * happened).
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                    const char *argv[])
{
    struct pam_args *args;
    int status;
    int pamret = PAM_SUCCESS;
    const void *dummy;

    args = pamafs_args_parse(flags, argc, argv);
    if (args == NULL) {
        pamafs_error("cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SESSION_ERR;
        goto done;
    }
    ENTRY(args, flags);

    /* Do nothing unless AFS is available. */
    if (!k_hasafs()) {
        pamafs_error("skipping, AFS apparently not available");
        goto done;
    }

    /*
     * Unless nopag is set or we've already created a PAG, always create a
     * PAG.  Do this even if we're otherwise ignoring the user.
     */
    status = pam_get_data(pamh, "pam_afs_session", &dummy);
    if (status == PAM_SUCCESS) {
        pamafs_debug(args, "skipping, apparently already ran");
        goto done;
    }
    if (!args->nopag && k_setpag() != 0) {
        pamafs_error("PAG creation failed: %s", strerror(errno));
        pamret = PAM_SESSION_ERR;
        goto done;
    }

    /* Get tokens. */
    if (!args->notokens)
        pamret = pamafs_token_get(pamh, args);

done:
    EXIT(args, pamret);
    pamafs_args_free(args);
    return pamret;
}

/*
 * Don't do anything for authenticate.  We're only an auth module so that we
 * can supply a pam_setcred implementation.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                    const char *argv[])
{
    return PAM_SUCCESS;
}


/*
 * Calling pam_setcred with PAM_ESTABLISH_CRED is equivalent to opening a new
 * session for our purposes.  With PAM_REFRESH_CRED, we don't call setpag,
 * just run aklog again.  PAM_DELETE_CRED calls unlog.
 */
int 
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
               const char *argv[])
{
    struct pam_args *args;
    int status;
    int pamret = PAM_SUCCESS;
    const void *dummy;

    args = pamafs_args_parse(flags, argc, argv);
    if (args == NULL) {
        pamafs_error("cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SESSION_ERR;
        goto done;
    }
    ENTRY(args, flags);

    /* Do nothing unless AFS is available. */
    if (!k_hasafs()) {
        pamafs_error("skipping, AFS apparently not available");
        goto done;
    }

    /* If DELETE_CRED was specified, delete the tokens (if any). */
    if (flags & PAM_DELETE_CRED) {
        if (args->retain || args->notokens)
            pamafs_debug(args, "skipping as configured");
        else
            pamret = pamafs_token_delete(pamh, args);
        goto done;
    }

    /*
     * We're acquiring tokens.  See if we already have done this and don't do
     * it again if we have unless we were explicitly told to reinitialize.  If
     * we're reinitializing, we may be running in a screen saver or the like
     * and should use the existing PAG, so don't create a new PAG.
     */
    if (!(flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED))) {
        status = pam_get_data(pamh, "pam_afs_session", &dummy);
        if (status == PAM_SUCCESS) {
            pamafs_debug(args, "skipping, apparently already ran");
            goto done;
        }
        if (!args->nopag && k_setpag() != 0) {
            pamafs_error("PAG creation failed: %s", strerror(errno));
            pamret = PAM_SESSION_ERR;
            goto done;
        }
    }
    if (!args->notokens)
        pamret = pamafs_token_get(pamh, args);

done:
    EXIT(args, pamret);
    pamafs_args_free(args);
    return pamret;
}


/*
 * Close a session.  Normally, what we do here is call unlog, but we can be
 * configured not to do so.
 */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                     const char *argv[])
{
    struct pam_args *args;
    int pamret = PAM_SUCCESS;

    args = pamafs_args_parse(flags, argc, argv);
    if (args == NULL) {
        pamafs_error("cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SESSION_ERR;
        goto done;
    }
    ENTRY(args, flags);

    /* Do nothing if so configured. */
    if (args->retain || args->notokens) {
        pamafs_debug(args, "skipping as configured");
        goto done;
    }

    /* Do nothing unless AFS is available. */
    if (!k_hasafs()) {
        pamafs_error("skipping, AFS apparently not available");
        goto done;
    }

    /* Delete tokens. */
    pamret = pamafs_token_delete(pamh, args);

done:
    EXIT(args, pamret);
    pamafs_args_free(args);
    return pamret;
}
