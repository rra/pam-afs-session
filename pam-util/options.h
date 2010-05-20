/*
 * Interface to PAM option parsing.
 *
 * This interface defines a lot of macros and types with very short names, and
 * hence without a lot of namespace protection.  It should be included only in
 * the file that's doing the option parsing and not elsewhere to remove the
 * risk of clashes.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef PAM_UTIL_OPTIONS_H
#define PAM_UTIL_OPTIONS_H 1

#include <config.h>
#include <portable/macros.h>
#include <portable/stdbool.h>

#ifdef HAVE_KERBEROS
# include <krb5.h>
#endif
#include <sys/types.h>

/* Forward declarations to avoid additional includes. */
struct vector;

/* The types of configuration values possible. */
enum type {
    TYPE_BOOLEAN,
    TYPE_NUMBER,
    TYPE_STRING,
    TYPE_LIST
};

/*
 * Each configuration option is defined by a struct option.  This specifies
 * the name of the option, its offset into the configuration struct, whether
 * it can be specified in a krb5.conf file, its type, and its default value if
 * not set.  Note that PAM configuration options are specified as strings, so
 * there's no native way of representing a list argument.  List values are
 * always initialized by splitting a string on whitespace or commas.
 *
 * The default value should really be a union, but you can't initialize unions
 * properly in C in a static initializer without C99 named initializer
 * support, which we can't (yet) assume.  So use a struct instead, and
 * initialize all the members, even though we'll only care about one of them.
 *
 * Note that numbers set in the configuration struct created by this interface
 * must be longs, not ints.  There is currently no provision for unsigned
 * numbers.
 *
 * Default string values are copied into the structure, but default list
 * values are not, so be careful about how memory is freed if you use a
 * default list value other than NULL.
 */
struct option {
    const char *name;
    size_t location;
    bool krb5_config;
    enum type type;
    struct {
        bool boolean;
        long number;
        const char *string;
        struct vector *list;
    } defaults;
};

/*
 * The following macros are helpers to make it easier to define the table that
 * specifies how to convert the configuration into a struct.  They provide an
 * initializer for the type and default fields.
 */
#define BOOL(def)   TYPE_BOOLEAN, { (def),     0,  NULL,  NULL }
#define NUMBER(def) TYPE_NUMBER,  {     0, (def),  NULL,  NULL }
#define STRING(def) TYPE_STRING,  {     0,     0, (def),  NULL }
#define LIST(def)   TYPE_LIST,    {     0,     0,  NULL, (def) }

/*
 * The user of this file should also define a macro of the following form:
 *
 *     #define K(name) (#name), offsetof(struct config, name)
 *
 * replacing struct config with the name of the configuration struct.  Then,
 * the definition of the necessary table for building the configuration will
 * look something like this:
 *
 *     const struct option options[] = {
 *         { K(aklog_homedir), true,  BOOL   (false) },
 *         { K(cells),         true,  LIST   (NULL)  },
 *         { K(debug),         false, BOOL   (false) },
 *         { K(minimum_uid),   true,  NUMBER (0)     },
 *         { K(program),       true,  STRING (NULL)  },
 *     };
 *
 * which provides a nice, succinct syntax for creating the table.  The options
 * MUST be in sorted order, since the options parsing code does a binary
 * search.
 */

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/*
 * Fill out options from krb5.conf.  Takes the PAM args structure, the name of
 * the section for the software being configured, and an option table defined
 * as above.  The config member of the args struct must already be allocated.
 * Only those options whose krb5_config attribute is true will be considered.
 *
 * This code automatically checks for configuration settings scoped to the
 * local realm, so the default realm should be set before calling this
 * function.  If that's done based on a configuration option, one may need to
 * pre-parse the configuration options.
 *
 * Returns true on success and false on an error.  An error return should be
 * considered fatal.  Errors will already be reported using putil_crit*() or
 * putil_err*() as appropriate.
 */
#ifdef HAVE_KERBEROS
bool putil_args_krb5(struct pam_args *, const char *section,
                     const struct option options[], size_t optlen)
    __attribute__((__nonnull__));
#endif

/*
 * Parse the PAM arguments and fill out the provided struct.  Takes the PAM
 * arguments, the argument count and vector, and an option table defined as
 * above.  The config member of the args struct must already be allocated.
 * Returns true on success and false on error.  An error return should be
 * considered fatal.  Errors will already be reported using putil_crit().
 * Unknown options will also be diagnosed (to syslog at LOG_ERR using
 * putil_err()), but are not considered fatal errors and will still return
 * true.
 *
 * The krb5_config option of the option configuration is ignored by this
 * function.  If options should be retrieved from krb5.conf, call
 * putil_args_krb5() first, before calling this function.
 */
bool putil_args_parse(struct pam_args *, int argc, const char *argv[],
                      const struct option options[], size_t optlen)
    __attribute__((__nonnull__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PAM_UTIL_OPTIONS_H */
