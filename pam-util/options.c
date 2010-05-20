/*
 * Parse PAM options into a struct.
 *
 * Given a struct in which to store options and a specification for what
 * options go where, parse both the PAM configuration options and any options
 * from a Kerberos krb5.conf file and fill out the struct.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#ifdef HAVE_KERBEROS
# include <portable/krb5.h>
#endif
#include <portable/system.h>

#include <errno.h>

#include <pam-util/args.h>
#include <pam-util/logging.h>
#include <pam-util/options.h>
#include <pam-util/vector.h>

/*
 * Macros used to resolve a void * pointer to the configuration struct and an
 * offset into a pointer to the appropriate type.  Scary violations of the C
 * type system lurk here.
 */
#define CONF_BOOL(c, o)   (bool *)          (void *)((char *) (c) + (o))
#define CONF_NUMBER(c, o) (long *)          (void *)((char *) (c) + (o))
#define CONF_STRING(c, o) (char **)         (void *)((char *) (c) + (o))
#define CONF_LIST(c, o)   (struct vector **)(void *)((char *) (c) + (o))


#ifdef HAVE_KERBEROS
/*
 * Load a boolean option from Kerberos appdefaults.  Takes the PAM argument
 * struct, the section name, the realm, the option, and the result location.
 *
 * The stupidity of rewriting the realm argument into a krb5_data is required
 * by MIT Kerberos.
 */
static void
default_boolean(struct pam_args *args, const char *section, const char *realm,
                const char *opt, bool defval, bool *result)
{
    int tmp;
#ifdef HAVE_KRB5_REALM
    krb5_const_realm realm_data = realm;
#else
    krb5_data realm_struct;
    const krb5_data *realm_data = &realm_struct;

    realm_struct.magic = KV5M_DATA;
    realm_struct.data = (void *) realm;
    realm_struct.length = strlen(realm);
#endif

    /*
     * The MIT version of krb5_appdefault_boolean takes an int * and the
     * Heimdal version takes a krb5_boolean *, so hope that Heimdal always
     * defines krb5_boolean to int or this will require more portability work.
     */
    krb5_appdefault_boolean(args->ctx, section, realm_data, opt, defval, &tmp);
    *result = tmp;
}


/*
 * Load a number option from Kerberos appdefaults.  Takes the PAM argument
 * struct, the section name, the realm, the option, and the result location.
 * The native interface doesn't support numbers, so we actually read a string
 * and then convert.
 */
static void
default_number(struct pam_args *args, const char *section, const char *realm,
               const char *opt, int defval, long *result)
{
    char *tmp, *end;
#ifdef HAVE_KRB5_REALM
    krb5_const_realm realm_data = realm;
#else
    krb5_data realm_struct;
    const krb5_data *realm_data = &realm_struct;

    realm_struct.magic = KV5M_DATA;
    realm_struct.data = (void *) realm;
    realm_struct.length = strlen(realm);
#endif

    krb5_appdefault_string(args->ctx, section, realm_data, opt, "", &tmp);
    if (tmp == NULL || tmp[0] == '\0')
        *result = defval;
    else {
        errno = 0;
        *result = strtol(tmp, &end, 10);
        if (errno != 0 || *end != '\0') {
            putil_err(args, "invalid number in krb5.conf setting for %s: %s",
                      opt, tmp);
            *result = defval;
        }
    }
    if (tmp != NULL)
        free(tmp);
}


/*
 * Load a string option from Kerberos appdefaults.  Takes the PAM argument
 * struct, the section name, the realm, the option, the default value, and the
 * result location.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value, so we
 * don't return an error code.
 */
static void
default_string(struct pam_args *args, const char *section, const char *realm,
               const char *opt, const char *defval, char **result)
{
#ifdef HAVE_KRB5_REALM
    krb5_const_realm realm_data = realm;
#else
    krb5_data realm_struct;
    const krb5_data *realm_data = &realm_struct;

    realm_struct.magic = KV5M_DATA;
    realm_struct.data = (void *) realm;
    realm_struct.length = strlen(realm);
#endif

    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(args->ctx, section, realm_data, opt, defval,
                           result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}


/*
 * Load a list option from Kerberos appdefaults.  Takes the PAM arguments, the
 * context, the section name, the realm, the option, the default value, and
 * the result location.
 *
 * We may fail here due to memory allocation problems, in which case we return
 * false to indicate that PAM setup should abort.
 */
static bool
default_list(struct pam_args *args, const char *section, const char *realm,
             const char *opt, struct vector *defval, struct vector **result)
{
    char *tmp;

    default_string(args, section, realm, opt, NULL, &tmp);
    if (tmp == NULL)
        *result = defval;
    else {
        *result = vector_split_multi(tmp, " \t,", NULL);
        if (*result == NULL) {
            putil_crit(args, "cannot allocate vector: %s", strerror(errno));
            return false;
        }
    }
    return true;
}


/*
 * The public interface for getting configuration information from krb5.conf.
 * Takes the PAM arguments, the krb5.conf section, the options specification,
 * and the number of options in the options table.  The config member of the
 * args struct must already be allocated.  Iterate through the option list
 * and, for every option where krb5_config is true, see if it's set in the
 * Kerberos configuration.
 *
 * This looks obviously slow, but there haven't been any reports of problems
 * and there's no better interface.  But if you wonder where the cycles in
 * your computer are getting wasted, well, here's one place.
 */
bool
putil_args_krb5(struct pam_args *args, const char *section,
                const struct option options[], size_t optlen)
{
    size_t i;
    char *realm;

    /* Having no local realm may be intentional, so don't report an error. */
    if (krb5_get_default_realm(args->ctx, &realm) < 0)
        realm = NULL;
    for (i = 0; i < optlen; i++) {
        const struct option *opt = &options[i];

        switch (opt->type) {
        case TYPE_BOOLEAN:
            default_boolean(args, section, realm, opt->name,
                            opt->defaults.boolean,
                            CONF_BOOL(args->config, opt->location));
            break;
        case TYPE_NUMBER:
            default_number(args, section, realm, opt->name,
                           opt->defaults.number,
                           CONF_NUMBER(args->config, opt->location));
            break;
        case TYPE_STRING:
            default_string(args, section, realm, opt->name,
                           opt->defaults.string,
                           CONF_STRING(args->config, opt->location));
            break;
        case TYPE_LIST:
            if (!default_list(args, section, realm, opt->name,
                              opt->defaults.list,
                              CONF_LIST(args->config, opt->location)))
                return false;
            break;
        }
    }
    if (realm != NULL)
        krb5_free_default_realm(args->ctx, realm);
    return true;
}
#endif /* HAVE_KERBEROS */


/*
 * Set a vector argument to its default.  This needs to do a deep copy of the
 * vector so that we can safely free it when freeing the configuration.  Takes
 * the PAM argument struct, the pointer in which to store the vector, and the
 * default vector.  Returns true if the default was set correctly and false on
 * memory allocation failure, which is also reported with putil_crit().
 */
static bool
copy_default_list(struct pam_args *args, struct vector **setting,
                  const struct vector *defval)
{
    struct vector *result;
    size_t i;

    *setting = NULL;
    if (defval != NULL && defval->strings != NULL) {
        result = vector_new();
        if (result == NULL) {
            putil_crit(args, "cannot allocate memory: %s", strerror(errno));
            return false;
        }
        if (!vector_resize(result, defval->count)) {
            putil_crit(args, "cannot allocate memory: %s", strerror(errno));
            vector_free(result);
            return false;
        }
        for (i = 0; i < defval->count; i++)
            if (!vector_add(result, defval->strings[i])) {
                putil_crit(args, "cannot allocate memory: %s",
                           strerror(errno));
                vector_free(result);
                return false;
            }
    }
    *setting = result;
    return true;
}


/*
 * bsearch comparison function for finding PAM arguments in an array of struct
 * options.  We only compare up to the first '=' in the key so that we don't
 * have to munge the string before searching.
 */
static int
option_compare(const void *key, const void *member)
{
    const char *string = key;
    const struct option *option = member;
    const char *p;
    size_t length;
    int result;

    p = strchr(string, '=');
    if (p == NULL)
        return strcmp(string, option->name);
    else {
        length = (p - string);
        if (length == 0)
            return -1;
        result = strncmp(string, option->name, length);
        if (result == 0 && strlen(option->name) > length)
            return -1;
        return result;
    }
}


/*
 * Given a PAM argument, convert the value portion of the argument to a number
 * and store it in the provided location.  If the value is missing or isn't a
 * number, report an error and leave the location unchanged.
 */
static void
convert_number(struct pam_args *args, const char *arg, long *setting)
{
    const char *value;
    char *end;
    long result;

    value = strchr(arg, '=');
    if (value == NULL) {
        putil_err(args, "value missing for option %s", arg);
        return;
    }
    errno = 0;
    result = strtol(arg, &end, 10);
    if (errno != 0 || *end != '\0') {
        putil_err(args, "invalid number in setting: %s", arg);
        return;
    }
    *setting = result;
}


/*
 * Given a PAM argument, convert the value portion of the argument to a string
 * and store it in the provided location.  If the value is missing, report an
 * error and leave the location unchanged, returning true since that's a
 * non-fatal error.  If memory allocation fails, return false, since PAM setup
 * should abort.
 */
static bool
convert_string(struct pam_args *args, const char *arg, char **setting)
{
    const char *value;
    char *result;

    value = strchr(arg, '=');
    if (value == NULL) {
        putil_err(args, "value missing for option %s", arg);
        return true;
    }
    result = strdup(value);
    if (result == NULL) {
        putil_crit(args, "cannot allocate memory: %s", strerror(errno));
        return false;
    }
    *setting = result;
    return true;
}


/*
 * Given a PAM argument, convert the value portion of the argument to a vector
 * and store it in the provided location.  If the value is missing, report an
 * error and leave the location unchanged, returning true since that's a
 * non-fatal error.  If memory allocation fails, return false, since PAM setup
 * should abort.
 */
static bool
convert_list(struct pam_args *args, const char *arg, struct vector **setting)
{
    const char *value;
    struct vector *result;

    value = strchr(arg, '=');
    if (value == NULL) {
        putil_err(args, "value missing for option %s", arg);
        return true;
    }
    result = vector_split_multi(value, " \t,", NULL);
    if (result == NULL) {
        putil_crit(args, "cannot allocate vector: %s", strerror(errno));
        return false;
    }
    if (*setting != NULL)
        vector_free(*setting);
    *setting = result;
    return true;
}


/*
 * Parse the PAM arguments.  Takes the PAM argument struct, the argument count
 * and vector, the option table, and the number of elements in the option
 * table.  The config member of the args struct must already be allocated.
 * Returns true on success and false on error.  An error return should be
 * considered fatal.  Report errors using putil_crit().  Unknown options will
 * also be diagnosed (to syslog at LOG_ERR using putil_err()), but are not
 * considered fatal errors and will still return true.
 *
 * If options should be retrieved from krb5.conf, call putil_args_krb5()
 * first, before calling this function.
 */
bool
putil_args_parse(struct pam_args *args, int argc, const char *argv[],
                 const struct option options[], size_t optlen)
{
    int i;
    size_t opt;
    const struct option *option;

    /* First pass: set all the defaults. */
    for (opt = 0; opt < optlen; opt++) {
        bool *bp;
        long *lp;
        char **sp;
        struct vector **vp;

        switch (options[opt].type) {
        case TYPE_BOOLEAN:
            bp = CONF_BOOL(args->config, options[opt].location);
            *bp = options[opt].defaults.boolean;
            break;
        case TYPE_NUMBER:
            lp = CONF_NUMBER(args->config, options[opt].location);
            *lp = options[opt].defaults.number;
            break;
        case TYPE_STRING:
            sp = CONF_STRING(args->config, options[opt].location);
            if (options[opt].defaults.string == NULL)
                *sp = NULL;
            else {
                *sp = strdup(options[opt].defaults.string);
                if (*sp == NULL) {
                    putil_crit(args, "cannot allocate memory: %s",
                               strerror(errno));
                    return false;
                }
            }
            break;
        case TYPE_LIST:
            vp = CONF_LIST(args->config, options[opt].location);
            if (!copy_default_list(args, vp, options[opt].defaults.list))
                return false;
            break;
        }
    }

    /*
     * Second pass: find each option we were given and set the corresponding
     * configuration parameter.
     */
    for (i = 0; i < argc; i++) {
        option = bsearch(argv[i], options, optlen, sizeof(struct option),
                         option_compare);
        if (option == NULL) {
            putil_err(args, "unknown option %s", argv[i]);
            continue;
        }
        switch (option->type) {
        case TYPE_BOOLEAN:
            *(CONF_BOOL(args->config, option->location)) = true;
            break;
        case TYPE_NUMBER:
            convert_number(args, argv[i],
                           CONF_NUMBER(args->config, option->location));
            break;
        case TYPE_STRING:
            if (!convert_string(args, argv[i],
                                CONF_STRING(args->config, option->location)))
                return false;
            break;
        case TYPE_LIST:
            if (!convert_list(args, argv[i],
                              CONF_LIST(args->config, option->location)))
                return false;
            break;
        }
    }
    return true;
}
