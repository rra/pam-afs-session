/*
 * Option handling for pam-afs-session.
 *
 * Parses the PAM command line for options to pam-afs-session and fills out an
 * allocated structure with those details.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008
 *     Board of Trustees, Leland Stanford Jr. University
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* AIX doesn't have the appdefault functions. */
#ifdef HAVE_KERBEROS
# include <krb5.h>
# ifndef HAVE_KRB5_APPDEFAULT_STRING
#  include "compat-aix.c"
# endif
#endif

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
        if (args->afs_cells != NULL)
            free(args->afs_cells);
        if (args->cells != NULL)
            free(args->cells);
        if (args->program != NULL)
            free(args->program);
        free(args);
    }
}


#ifdef HAVE_KERBEROS
/*
 * Load a string option from Kerberos appdefaults.  This requires an annoying
 * workaround because one cannot specify a default value of NULL.
 */
static void
default_string(krb5_context c, const char *opt, const char *defval,
               char **result)
{
    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(c, "pam-afs-session", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}


/*
 * Load a number option from Kerberos appdefaults.  The native interface
 * doesn't support numbers, so we actually read a string and then convert.
 */
static void
default_number(krb5_context c, const char *opt, int defval, int *result)
{
    char *tmp;

    krb5_appdefault_string(c, "pam-afs-session", NULL, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0')
        *result = atoi(tmp);
    else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}


/*
 * Load a boolean option from Kerberos appdefaults.  This is a simple wrapper
 * around the Kerberos library function.
 */
static void
default_boolean(krb5_context c, const char *opt, int defval, int *result)
{
    krb5_appdefault_boolean(c, "pam-afs-session", NULL, opt, defval, result);
}


/*
 * Load configuration options from krb5.conf.  This is only done if we were
 * built with Kerberos support.  The list of options here should match the
 * options we recognize in the PAM configuration.
 */
static void
load_krb5_config(struct pam_args *args)
{
    krb5_context c;
    krb5_error_code retval;

    retval = krb5_init_context(&c);
    if (retval != 0) {
        pamafs_error_krb5(NULL, "cannot initialize Kerberos", retval);
        return;
    }
    default_string(c, "afs_cells", NULL, &args->afs_cells);
    default_boolean(c, "aklog_homedir", 0, &args->aklog_homedir);
    default_boolean(c, "always_aklog", 0, &args->always_aklog);
    default_boolean(c, "debug", 0, &args->debug);
    default_boolean(c, "ignore_root", 0, &args->ignore_root);
    default_boolean(c, "kdestroy", 0, &args->kdestroy);
    default_number(c, "minimum_uid", 0, &args->minimum_uid);
    default_boolean(c, "nopag", 0, &args->nopag);
    default_boolean(c, "notokens", 0, &args->notokens);
    default_string(c, "program", NULL, &args->program);
    default_boolean(c, "retain_after_close", 0, &args->retain);
}
#endif /* HAVE_KERBEROS */


/*
 * This is where we parse options.  Currently, only setting options in the PAM
 * arguments is supported.  It would be nice to also support getting options
 * from krb5.conf, but that requires linking with Kerberos libraries.
 */
struct pam_args *
pamafs_args_parse(int flags UNUSED, int argc, const char **argv)
{
    struct pam_args *args;
    int i;

    args = pamafs_args_new();
    if (args == NULL)
        return NULL;

    /*
     * If we were built with Kerberos support, start by trying to load our
     * configuration from krb5.conf.  We want anything in the PAM
     * configuration to override.
     */
#ifdef HAVE_KERBEROS
    load_krb5_config(args);
#endif

    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "afs_cells=", strlen("afs_cells=")) == 0) {
            if (args->afs_cells != NULL)
                free(args->afs_cells);
            args->afs_cells = strdup(&argv[i][strlen("afs_cells=")]);
        }
        else if (strcmp(argv[i], "aklog_homedir") == 0)
            args->aklog_homedir = 1;
        else if (strcmp(argv[i], "always_aklog") == 0)
            args->always_aklog = 1;
        else if (strcmp(argv[i], "debug") == 0)
            args->debug = 1;
        else if (strcmp(argv[i], "ignore_root") == 0)
            args->ignore_root = 1;
        else if (strcmp(argv[i], "kdestroy") == 0)
            args->kdestroy = 1;
        else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
            args->minimum_uid = atoi(&argv[i][strlen("minimum_uid=")]);
        else if (strcmp(argv[i], "nopag") == 0)
            args->nopag = 1;
        else if (strcmp(argv[i], "notokens") == 0)
            args->notokens = 1;
        else if (strncmp(argv[i], "program=", 8) == 0) {
            if (args->program != NULL)
                free(args->program);
            args->program = strdup(&argv[i][strlen("program=")]);
        }
        else if (strcmp(argv[i], "retain_after_close") == 0)
            args->retain = 1;
        else
            pamafs_error("unknown option %s", argv[i]);
    }

#if defined(PATH_AKLOG) && !defined(HAVE_KRB5_AFSLOG)
    if (args->program == NULL)
        args->program = strdup(PATH_AKLOG);
#endif

    /* Warn if kdestroy was set and we can't honor it. */
#ifndef HAVE_KERBEROS
    if (args->kdestroy)
        pamafs_error("kdestroy specified but not built with Kerberos support");
#endif

    /*
     * Turn afs_cells, which may be space and/or comma-separated, into a more
     * useful null-terminated array of cells.
     */
    if (args->afs_cells != NULL) {
        size_t count, i;
        char **new_cells;
        char *p = args->afs_cells;

        i = 0;
        count = 2;
        args->cells = malloc(count * sizeof(char *));
        if (args->cells == NULL)
            goto fail;
        while (*p != '\0') {
            while ((isspace((unsigned char) *p) || *p == ',') && *p != '\0') {
                *p = '\0';
                p++;
            }
            if (i >= count - 1) {
                count++;
                new_cells = realloc(args->cells, count * sizeof(char *));
                if (new_cells == NULL)
                    goto fail;
                args->cells = new_cells;
            }
            args->cells[i++] = p;
            while (!isspace((unsigned char) *p) && *p != ',' && *p != '\0')
                p++;
        }
        args->cells[i] = NULL;
        args->cell_count = i;
    }

    return args;

fail:
    pamafs_args_free(args);
    return NULL;
}
