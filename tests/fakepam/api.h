/*
 * Interface for fake PAM library, used for testing.
 *
 * This is the public interface for the fake PAM library, used for testing.
 * It declares only enough functions and data structures to allow PAM module
 * code to be linked with this library instead of the system libpam library
 * for testing purposes.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef FAKEPAM_API_H
#define FAKEPAM_API_H 1

#include <config.h>
#include <portable/macros.h>

/* Data structures standardized by the PAM API. */
struct pam_message {
    int msg_style;
    PAM_CONST char *msg;
};
struct pam_response {
    char *resp;
    int resp_retcode;
};
struct pam_conv {
    int (*conv)(int num_msg, PAM_CONST struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};

/*
 * Return codes.  On Linux at least, these are normally defines, but we use
 * enums instead.  The numbers here are the same as on Linux, to pick a
 * platform arbitrarily.  Only the ones we actually use are defined.
 */
enum pam_status {
    PAM_SUCCESS    = 0,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR    = 5
};

/* PAM data items.  The numbers are the same as Linux. */
enum pam_item {
    PAM_SERVICE    = 1,
    PAM_USER       = 2,
    PAM_TTY        = 3,
    PAM_RHOST      = 4,
    PAM_CONV       = 5,
    PAM_AUTHTOK    = 6,
    PAM_OLDAUTHTOK = 7,
    PAM_RUSER      = 8
};

/* This is an opaque data structure, so we can put whatever we want in it. */
typedef struct pam_handle {
    const char *service;
    const char *user;
    const struct pam_conv *conversation;
} pam_handle_t;

BEGIN_DECLS

/* Initialize the pam_handle_t used by all other PAM functions. */
int pam_start(const char *service_name, const char *user,
              const struct pam_conv *pam_conversation,
              pam_handle_t **pamh);

/* PAM logging and error reporting functions. */
const char *pam_strerror(pam_handle_t *, int);
void pam_syslog(const pam_handle_t *, int, const char *, ...);
void pam_vsyslog(const pam_handle_t *, int, const char *, va_list);

/* Setting and retrieving PAM data. */
int pam_get_item(const pam_handle_t *, int, const void **);

END_DECLS

#endif /* !FAKEPAM_API_H */
