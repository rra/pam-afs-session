/*
 * internal.h
 *
 * Internal prototypes and structures for pam_afs_session.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include "config.h"

#include <security/pam_modules.h>
#include <stdarg.h>

struct passwd;

/*
 * The global structure holding our arguments from the PAM configuration.
 * Filled in by pamafs_args_parse.
 */
struct pam_args {
    int debug;                  /* Log debugging information. */
    int ignore_root;            /* Skip authentication for root. */
    int minimum_uid;            /* Ignore users below this UID. */
    int nopag;                  /* Don't create a new PAG. */
    int retain;                 /* Don't destroy the cache on session end. */

    /*
     * This isn't really an arg, but instead flags whether PAM_SILENT was
     * included in the flags.  If set, don't report some messages back to the
     * user (currently only error messages from password changing).
     */
    int quiet;
};

/* Parse the PAM flags and arguments and fill out pam_args. */
struct pam_args *pamafs_args_parse(int flags, int argc, const char **argv);

/* Free the pam_args struct when we're done. */
void pamafs_args_free(struct pam_args *);

/* Returns true if we should ignore this user (root or low UID). */
int pamafs_should_ignore(struct pam_args *, const struct passwd *pwd);

/* Token manipulation functions. */
int pamafs_token_get(pam_handle_t *pamh, struct pam_args *args);
int pamafs_token_delete(pam_handle_t *pamh, struct pam_args *args);

/* Error reporting and debugging functions. */
void pamafs_error(struct context *, const char *, ...);
void pamafs_debug(struct context *, struct pam_args *, const char *, ...);
void pamafs_debug_pam(struct context *, struct pam_args *, const char *, int);

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(args, flags) \
    pamafs_debug((args), "%s: entry (0x%x)", __FUNCTION__, (flags))
#define EXIT(args, pamret) \
    pamafs_debug((args), "%s: exit (%s)", __FUNCTION__, \
                ((pamret) == PAM_SUCCESS) ? "success" : "failure")

#endif /* INTERNAL_H */
