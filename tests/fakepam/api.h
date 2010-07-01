/*
 * Interface for fake PAM library, used for testing.
 *
 * This is the public interface for the fake PAM library, used when testing
 * module code.  It declares only enough functions and data structures to
 * allow PAM module code to be linked with this library instead of the system
 * libpam library for testing purposes.  The functions used by the test suite
 * itself aren't defined here; for those, see <fakepam/testing.h>.
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

#include <stdarg.h>

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
    PAM_SUCCESS     = 0,
    PAM_OPEN_ERR    = 1,
    PAM_SYMBOL_ERR  = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR  = 4,
    PAM_BUF_ERR     = 5,
    PAM_SESSION_ERR = 14,
    PAM_CONV_ERR    = 19,
    PAM_IGNORE      = 25
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

/* PAM flags.  The numbers are the same as Linux. */
enum pam_flag {
    PAM_ESTABLISH_CRED    = 0x0002U,
    PAM_DELETE_CRED       = 0x0004U,
    PAM_REINITIALIZE_CRED = 0x0008U,
    PAM_REFRESH_CRED      = 0x0010U,
    PAM_SILENT            = 0x8000U
};

/* pam_handle_t is opaque to clients. */
struct pam_handle;
typedef struct pam_handle pam_handle_t;

BEGIN_DECLS

/* PAM logging and error reporting functions. */
const char *pam_strerror(pam_handle_t *, int);
void pam_syslog(const pam_handle_t *, int, const char *, ...);
void pam_vsyslog(const pam_handle_t *, int, const char *, va_list);

/* Setting and retrieving PAM data. */
int pam_get_data(const pam_handle_t *, const char *, PAM_CONST void **);
int pam_get_item(const pam_handle_t *, int, PAM_CONST void **);
int pam_get_user(const pam_handle_t *, PAM_CONST char **, const char *);
int pam_set_data(pam_handle_t *, const char *, void *,
                 void (*)(pam_handle_t *, void *, int));

/* Manipulating the environment. */
const char *pam_getenv(pam_handle_t *, const char *);
char **pam_getenvlist(pam_handle_t *);
int pam_putenv(pam_handle_t *, const char *);

/* Module functions. */
int pam_sm_authenticate(pam_handle_t *, int, int, const char **);
int pam_sm_setcred(pam_handle_t *, int, int, const char **);
int pam_sm_acct_mgmt(pam_handle_t *, int, int, const char **);
int pam_sm_open_session(pam_handle_t *, int, int, const char **);
int pam_sm_close_session(pam_handle_t *, int, int, const char **);
int pam_sm_chauthtok(pam_handle_t *, int, int, const char **);

END_DECLS

#endif /* !FAKEPAM_API_H */
