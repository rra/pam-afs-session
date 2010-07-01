/*
 * Interface for fake PAM library, used for testing.
 *
 * This contains most interfaces for the fake PAM library, used for testing.
 * It declares only the functions required to allow PAM module code to be
 * linked with this library instead of the system libpam library for testing
 * purposes.
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
 * Initializes the pam_handle_t data structure.  This function is only called
 * from test programs, not from any of the module code.  We can put anything
 * we want in this structure, since it's opaque to the regular code.
 */
int
pam_start(const char *service_name, const char *user,
          const struct pam_conv *pam_conversation,
          pam_handle_t **pamh)
{
    struct pam_handle *handle;

    handle = malloc(sizeof(struct pam_handle));
    if (handle == NULL)
        return PAM_BUF_ERR;
    handle->service = service_name;
    handle->user = user;
    handle->conversation = pam_conversation;
    *pamh = handle;
    return PAM_SUCCESS;
}


/*
 * Free the pam_handle_t data structure and related resources.  This is not
 * strictly necessary since it's only used for testing, but it helps keep our
 * memory usage clean so that we can run the test suite under valgrind.
 */
int
pam_end(pam_handle_t *pamh, int status UNUSED)
{
    free(pamh);
    return PAM_SUCCESS;
}


/*
 * The following functions are just stubs for right now and always fail.
 */
int
pam_get_data(const pam_handle_t *pamh UNUSED, const char *name UNUSED,
             PAM_CONST void **data UNUSED)
{
    return PAM_SYSTEM_ERR;
}
int
pam_get_item(const pam_handle_t *pamh UNUSED, int item UNUSED,
             PAM_CONST void **data UNUSED)
{
    return PAM_SYSTEM_ERR;
}
int
pam_set_data(pam_handle_t *pamh UNUSED, const char *item UNUSED,
             void *data UNUSED, pam_callback_type callback UNUSED)
{
    return PAM_SYSTEM_ERR;
}
const char *
pam_getenv(pam_handle_t *pamh UNUSED, const char *name UNUSED)
{
    return NULL;
}
char **
pam_getenvlist(pam_handle_t *pamh UNUSED)
{
    return NULL;
}
int
pam_putenv(pam_handle_t *pamh UNUSED, const char *setting UNUSED)
{
    return PAM_SYSTEM_ERR;
}
