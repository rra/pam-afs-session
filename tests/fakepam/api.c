/*
 * Interface for fake PAM library, used for testing.
 *
 * This is the public interface for the fake PAM library, used for testing.
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
 * The following functions are just stubs for right now and always fail.
 */
const char *
pam_strerror(pam_handle_t *pamh UNUSED, int code UNUSED)
{
    return NULL;
}
void
pam_syslog(const pam_handle_t *pamh UNUSED, int code UNUSED,
           const char *format UNUSED, ...)
{
}
void
pam_vsyslog(const pam_handle_t *pamh UNUSED, int code UNUSED,
            const char *format UNUSED, va_list args UNUSED)
{
}
int
pam_get_item(const pam_handle_t *pamh UNUSED, int item UNUSED,
             const void **data UNUSED)
{
    return PAM_SYSTEM_ERR;
}
