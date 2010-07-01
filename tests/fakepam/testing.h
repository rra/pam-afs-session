/*
 * Testing interfaces to the fake PAM library.
 *
 * This header defines the interfaces to the fake PAM library that are used by
 * test code to initialize the library and recover test data from it.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */
 
#ifndef FAKEPAM_TESTING_H
#define FAKEPAM_TESTING_H 1

#include <config.h>
#include <portable/macros.h>

#include <tests/fakepam/api.h>

/* This is an opaque data structure, so we can put whatever we want in it. */
struct pam_handle {
    const char *service;
    const char *user;
    const struct pam_conv *conversation;
};

/* The type used for the data callback function. */
typedef void (*pam_callback_type)(pam_handle_t *, void *, int);

BEGIN_DECLS

/* Initialize the pam_handle_t used by all other PAM functions. */
int pam_start(const char *service_name, const char *user,
              const struct pam_conv *, pam_handle_t **);

/* Free the pam_handle_t and associated resources. */
int pam_end(pam_handle_t *, int);

/*
 * Returns the accumulated messages logged with pam_syslog or pam_vsyslog
 * since the last call to pam_output and then clears the output.  Returns
 * newly allocated memory that the caller is responsible for freeing, or NULL
 * if no output has been logged since the last call or since startup.
 */
char *pam_output(void);

END_DECLS

#endif /* !FAKEPAM_API_H */
