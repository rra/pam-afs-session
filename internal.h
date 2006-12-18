/*
 * internal.h
 *
 * Internal prototypes and structures for pam_afs_session.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include "config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <stdarg.h>

struct passwd;

/*
 * The global structure holding our arguments from the PAM configuration.
 * Filled in by pamafs_args_parse.
 */
struct pam_args {
    int aklog_homedir;          /* Pass -p <homedir> to aklog. */
    int always_aklog;           /* Always run aklog even w/o KRB5CCNAME. */
    int debug;                  /* Log debugging information. */
    int ignore_root;            /* Skip authentication for root. */
    int kdestroy;               /* Destroy ticket cache after aklog. */
    int minimum_uid;            /* Ignore users below this UID. */
    int nopag;                  /* Don't create a new PAG. */
    char *program;              /* Program to run for tokens. */
    int retain;                 /* Don't destroy the cache on session end. */
};

/* Parse the PAM flags and arguments and fill out pam_args. */
struct pam_args *pamafs_args_parse(int flags, int argc, const char **argv);

/* Free the pam_args struct when we're done. */
void pamafs_args_free(struct pam_args *);

/* Token manipulation functions. */
int pamafs_token_get(pam_handle_t *pamh, struct pam_args *args);
int pamafs_token_delete(pam_handle_t *pamh, struct pam_args *args);

/* Error reporting and debugging functions. */
void pamafs_error(const char *, ...);
void pamafs_debug(struct pam_args *, const char *, ...);

/* __func__ is C99, but not provided by all implementations. */
#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(args, flags) \
    pamafs_debug((args), "%s: entry (0x%x)", __func__, (flags))
#define EXIT(args, pamret) \
    pamafs_debug((args), "%s: exit (%s)", __func__, \
                ((pamret) == PAM_SUCCESS) ? "success" : "failure")

#endif /* INTERNAL_H */
