/*
 * Data manipulation functions for the fake PAM library, used for testing.
 *
 * This file contains the implementation of pam_get_* and pam_set_* for the
 * various data items supported by the PAM library.
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

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))


/*
 * Return the user for the PAM context.
 */
int
pam_get_user(const pam_handle_t *pamh, PAM_CONST char **user,
             const char *prompt UNUSED)
{
    if (pamh->user == NULL)
        return PAM_CONV_ERR;
    else {
        *user = (char *) pamh->user;
        return PAM_SUCCESS;
    }
}
