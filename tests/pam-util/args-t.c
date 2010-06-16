/*
 * PAM utility argument initialization test suite.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/stdbool.h>
#include <portable/system.h>

#include <tests/fakepam/api.h>
#include <tests/tap/basic.h>

#define TESTING 1
#include <pam-util/args.h>


int
main(void)
{
    pam_handle_t *pamh;
    struct pam_args *args;

    plan(7);

    if (pam_start(NULL, NULL, NULL, &pamh) != PAM_SUCCESS)
        sysbail("Fake PAM initialization failed");
    args = putil_args_new(pamh);
    ok(args != NULL, "New args struct is not NULL");
    ok(args->pamh == pamh, "...and pamh is correct");
    ok(args->config == NULL, "...and config is NULL");
    ok(args->user == NULL, "...and user is NULL");
    is_int(args->debug, false, "...and debug is false");
#ifdef HAVE_KERBEROS
    ok(args->ctx != NULL, "...and the Kerberos context is initialized");
#else
    skip("Kerberos support not configured");
#endif
    putil_args_free(args);
    ok(1, "Freeing the args struct works");

    return 0;
}
