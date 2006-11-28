/*
 * options.c
 *
 * Option handling for pam_afs_session.
 *
 * Parses the PAM command line for options to pam_afs_session and fills out an
 * allocated structure with those details.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "internal.h"

/*
 * Allocate a new struct pam_args and initialize its data members.
 */
static struct pam_args *
pamafs_args_new(void)
{
    struct pam_args *args;

    args = calloc(1, sizeof(struct pam_args));
    if (args == NULL)
        return NULL;
    args->program = NULL;
    return args;
}

/*
 * Free the allocated args struct and any memory it points to.
 */
void
pamafs_args_free(struct pam_args *args)
{
    if (args != NULL) {
        if (args->program != NULL)
            free(args->program);
        free(args);
    }
}

/*
 * This is where we parse options.  Currently, only setting options in the PAM
 * arguments is supported.  It would be nice to also support getting options
 * from krb5.conf, but that requires linking with Kerberos libraries.
 */
struct pam_args *
pamafs_args_parse(int flags, int argc, const char **argv)
{
    struct pam_args *args;
    int i;

    args = pamafs_args_new();
    if (args == NULL)
        return NULL;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "aklog_homedir") == 0)
            args->aklog_homedir = 1;
        else if (strcmp(argv[i], "always_aklog") == 0)
            args->always_aklog = 1;
        else if (strcmp(argv[i], "debug") == 0)
            args->debug = 1;
        else if (strcmp(argv[i], "ignore_root") == 0)
            args->ignore_root = 1;
        else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
            args->minimum_uid = atoi(&argv[i][strlen("minimum_uid=")]);
        else if (strcmp(argv[i], "nopag") == 0)
            args->nopag = 1;
        else if (strncmp(argv[i], "program=", 8) == 0)
            args->program = strdup(&argv[i][strlen("program=")]);
        else if (strcmp(argv[i], "retain_after_close") == 0)
            args->retain = 1;
        else
            pamafs_error(NULL, "unknown option %s", argv[i]);
    }

#ifdef PATH_AKLOG
    if (args->program == NULL)
        args->program = strdup(PATH_AKLOG);
#endif
	
    if (flags & PAM_SILENT)
        args->quiet++;

    return args;
}
