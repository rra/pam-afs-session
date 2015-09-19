/*
 * Stubs to support testing a module without some PAM groups.
 *
 * pam-afs-session doesn't support account management or password changes, but
 * these are wired into the PAM testing apparatus.  Provide stub functions so
 * that the test programs will link.
 *
 * Copyright 2015 Russ Allbery <eagle@eyrie.org>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>

#include <tests/tap/macros.h>


int
pam_sm_acct_mgmt(pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED,
                 const char **argv UNUSED)
{
    return PAM_SUCCESS;
}


int
pam_sm_chauthtok(pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED,
                 const char **argv UNUSED)
{
    return PAM_SUCCESS;
}
