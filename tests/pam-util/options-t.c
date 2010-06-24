/*
 * PAM option parsing test suite.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/fakepam/api.h>
#include <tests/fakepam/testing.h>
#include <tests/tap/basic.h>

#define TESTING 1
#include <pam-util/args.h>
#include <pam-util/options.h>
#include <pam-util/vector.h>

/* The configuration struct we will use for testing. */
struct pam_config {
    struct vector *cells;
    bool debug;
    bool ignore_root;
    long minimum_uid;
    char *program;
};

#define K(name) (#name), offsetof(struct pam_config, name)

/* The rules specifying the configuration options. */
struct option options[] = {
    { K(cells),       false, LIST   (NULL)  },
    { K(debug),       false, BOOL   (false) },
    { K(ignore_root), false, BOOL   (true)  },
    { K(minimum_uid), false, NUMBER (0)     },
    { K(program),     false, STRING (NULL)  },
};
const size_t optlen = sizeof(options) / sizeof(options[0]);


/*
 * Allocate and initialize a new struct config.
 */
static struct pam_config *
config_new(void)
{
    struct pam_config *config;

    config = calloc(1, sizeof(struct pam_config));
    if (config == NULL)
        sysbail("cannot allocate memory");
    config->cells = NULL;
    config->program = NULL;
    return config;
}


/*
 * Free a struct config and all of its members.
 */
static void
config_free(struct pam_config *config)
{
    if (config->cells != NULL)
        vector_free(config->cells);
    if (config->program != NULL)
        free(config->program);
    free(config);
}


int
main(void)
{
    pam_handle_t *pamh;
    struct pam_args *args;
    bool status;
    const char *argv_empty[] = { NULL };
    const char *argv_all[] = {
        "cells=stanford.edu,ir.stanford.edu", "debug", "ignore_root",
        "minimum_uid=1000", "program=/bin/true"
    };

    if (pam_start(NULL, NULL, NULL, &pamh) != PAM_SUCCESS)
        sysbail("cannot create pam_handle_t");
    args = putil_args_new(pamh);
    if (args == NULL)
        sysbail("cannot create PAM argument struct");

    plan(15);

    /* First, check just the defaults. */
    args->config = config_new();
    status = putil_args_parse(args, 0, argv_empty, options, optlen);
    ok(status, "Parse of empty argv");
    ok(args->config->cells == NULL, "...cells default");
    is_int(false, args->config->debug, "...debug default");
    is_int(true, args->config->ignore_root, "...ignore_root default");
    is_int(0, args->config->minimum_uid, "...minimum_uid default");
    ok(args->config->program == NULL, "...program default");
    config_free(args->config);
    args->config = NULL;

    /* Now, check setting everything. */
    args->config = config_new();
    status = putil_args_parse(args, 5, argv_all, options, optlen);
    ok(status, "Parse of full argv");
    ok(args->config->cells != NULL, "...cells is set");
    is_int(2, args->config->cells->count, "...with two cells");
    is_string("stanford.edu", args->config->cells->strings[0],
              "...first is stanford.edu");
    is_string("ir.stanford.edu", args->config->cells->strings[1],
              "...second is ir.stanford.edu");
    is_int(true, args->config->debug, "...debug is set");
    is_int(true, args->config->ignore_root, "...ignore_root is set");
    is_int(1000, args->config->minimum_uid, "...minimum_uid is set");
    is_string("/bin/true", args->config->program, "...program is set");
    config_free(args->config);
    args->config = NULL;

    return 0;
}
