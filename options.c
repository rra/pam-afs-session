/*
 * Option handling for pam-afs-session.
 *
 * Parses the PAM command line for options to pam-afs-session and fills out an
 * allocated structure with those details.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>
#include <pam-util/options.h>
#include <pam-util/vector.h>

#ifdef HAVE_KRB5_AFSLOG
# undef PATH_AKLOG
#endif
#if !defined(PATH_AKLOG)
# define PATH_AKLOG NULL
#endif

/* Our option definition. */
#define K(name) (#name), offsetof(struct pam_config, name)
static const struct option options[] = {
    { K(afs_cells),          true, LIST    (NULL)       },
    { K(aklog_homedir),      true, BOOL    (false)      },
    { K(always_aklog),       true, BOOL    (false)      },
    { K(debug),              true, BOOL    (false)      },
    { K(ignore_root),        true, BOOL    (false)      },
    { K(kdestroy),           true, BOOL    (false)      },
    { K(minimum_uid),        true, NUMBER  (0)          },
#ifdef NO_PAG_SUPPORT
    { K(nopag),              true, BOOL    (true)       },
#else
    { K(nopag),              true, BOOL    (false)      },
#endif
    { K(notokens),           true, BOOL    (false)      },
    { K(program),            true, STRLIST (PATH_AKLOG) },
    { K(retain_after_close), true, BOOL    (false)      },
};
static const size_t optlen = sizeof(options) / sizeof(options[0]);


/*
 * Allocate a new struct pam_args and initialize its data members, including
 * parsing the arguments and getting settings from krb5.conf.
 */
struct pam_args *
pamafs_init(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_args *args;

    args = putil_args_new(pamh, flags);
    if (args == NULL)
        return NULL;
    args->config = calloc(1, sizeof(struct pam_config));
    if (args->config == NULL) {
        putil_crit(args, "cannot allocate memory: %s", strerror(errno));
        putil_args_free(args);
        return NULL;
    }
    if (!putil_args_defaults(args, options, optlen)) {
        free(args->config);
        putil_args_free(args);
        return NULL;
    }
    if (!putil_args_krb5(args, "pam-afs-session", options, optlen))
        goto fail;
    if (!putil_args_parse(args, argc, argv, options, optlen))
        goto fail;
    if (args->config->debug)
        args->debug = true;

    /* UIDs are unsigned on some systems. */
    if (args->config->minimum_uid < 0)
        args->config->minimum_uid = 0;

    /* Warn if kdestroy was set and we can't honor it. */
#ifndef HAVE_KERBEROS
    if (args->config->kdestroy)
        putil_err(args, "kdestroy specified but not built with Kerberos"
                  " support");
#endif

    return args;

fail:
    pamafs_free(args);
    return NULL;
}


/*
 * Free the allocated args struct and any memory it points to.
 */
void
pamafs_free(struct pam_args *args)
{
    if (args == NULL)
        return;
    if (args->config != NULL) {
        if (args->config->afs_cells != NULL)
            vector_free(args->config->afs_cells);
        if (args->config->program != NULL)
            free(args->config->program);
        free(args->config);
        args->config = NULL;
    }
    putil_args_free(args);
}
