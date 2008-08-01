dnl Process this file with Autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007, 2008
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.61])
AC_INIT([pam-afs-session], [1.7], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])

m4_include([m4/krb5.m4])
m4_include([m4/lib-depends.m4])
m4_include([m4/pam-const.m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
AC_AIX
AC_HEADER_STDC

dnl Determine the path to aklog.  If we can't figure it out, the user will
dnl have to set program in the PAM options.
AC_ARG_WITH([aklog],
    AC_HELP_STRING([--with-aklog=PATH],
        [Path to aklog or other Kerberos v5 AFS token program]),
    [AS_IF([test x"$withval" != xno], [PATH_AKLOG="$withval"])],
    [AC_PATH_PROGS([PATH_AKLOG], [aklog])])
AS_IF([test -n "$PATH_AKLOG"],
    [AC_DEFINE_UNQUOTED([PATH_AKLOG], ["$PATH_AKLOG"],
        [Full path to aklog binary.])])

dnl Let the user tell us where their AFS headers are.
AC_ARG_WITH([afs-headers],
    AC_HELP_STRING([--with-afs-headers=PATH],
        [Path to OpenAFS headers (for syscall number)]),
    [AS_IF([test x"$withval" != xno], [CPPFLAGS="-I$withval $CPPFLAGS"])])

dnl Crank up the warnings if we're using GCC.
AS_IF([test "$GCC" = "yes"], [CFLAGS="-Wall $CFLAGS"])

dnl We can optionally build with Kerberos libraries so that we can use
dnl Kerberos calls to get configuration information.  Check this before
dnl checking for libkafs.
RRA_LIB_KRB5_OPTIONAL
RRA_LIB_KRB5_SET
AS_IF([test x"$rra_use_kerberos" != xfalse],
    [AC_CHECK_HEADERS([k5profile.h])
     AC_CHECK_FUNCS([krb5_appdefault_string])])

dnl Figure out how we're going to get the kafs functions.  We only need
dnl k_hasafs, k_setpag, and k_unlog.  On Linux only, we can fall back to our
dnl internal implementation; otherwise, we have to have a library.
libkafs=true
AC_ARG_WITH([libkafs],
    AC_HELP_STRING([--without-libkafs],
        [Always use internal AFS syscall code]),
    [AS_IF([test x"$withval" = xno], [libkafs=false])])
AS_IF([test x"$libkafs" != xfalse],
    [AC_CHECK_LIB([kafs], [k_hasafs],
        [LIBS="-lkafs $LIBS"
         AC_CHECK_HEADERS([kafs.h])],
        [AC_CHECK_LIB([kopenafs], [k_hasafs],
            [LIBS="-lkopenafs $LIBS"
             AC_CHECK_HEADERS([kopenafs.h])],
            [libkafs=false])])])
AS_IF([test x"$libkafs" = xtrue],
    [AC_CHECK_FUNCS([krb5_afslog])],
    [case "$host" in
    *-linux*)
        AC_LIBOBJ([sys-api])
        AC_LIBOBJ([sys-linux])
        ;;
    *)
        AC_CHECK_HEADERS([afs/param.h],
            [AC_LIBOBJ([sys-api])
             AC_LIBOBJ([sys-syscall])],
            [AC_MSG_ERROR([No suitable kafs implementation found])])
        ;;
    esac])

dnl Other portability checks.  Mac OS X calls its PAM headers something
dnl different than everyone else.
LIBS="-lpam $LIBS"
AC_CHECK_FUNCS([pam_getenv pam_getenvlist])
AC_CHECK_HEADERS([sys/ioccom.h])
AC_TYPE_SIGNAL
AC_CHECK_HEADERS([security/pam_appl.h], ,
    [AC_CHECK_HEADERS([pam/pam_appl.h], ,
        [AC_MSG_ERROR([No PAM header files found])])])
RRA_HEADER_PAM_CONST

dnl Needed to get a prototype for environ on Linux.
AC_DEFINE([_GNU_SOURCE], [1], [Define to 1 on Linux to get full prototypes.])

dnl Needed for correct handling of errno with threaded applications on
dnl Solaris.
AC_DEFINE([_REENTRANT], [1],
    [Define to 1 on Solaris for correct errno handling with threads.])

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.
dnl
dnl Also, if and only if we're on Linux, make sure that all the symbols in the
dnl module are resolved, try to adjust for the 32-bit vs. 64-bit library
dnl paths, and use a version script to be sure that we hide internal
dnl functions.  The version script could also be used on Solaris and probably
dnl other ELF platforms, but the option is only valid with the GNU ld and I
dnl don't know how to probe for that.
dnl
dnl More platforms could be handled here.  Contributions welcome.
MAP="-Wl,--version-script=pam_afs_session.map"
case "$host" in
*-aix*)
    AS_IF([test "$GCC" = "yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LD="$CC"
         LDFLAGS="-fPIC -shared $LDFLAGS"],
        [LD=ld
         LDFLAGS="-G -bnoentry -bexpall $LDFLAGS"])
    ;;
*-darwin*)
    AS_IF([test "$GCC" = "yes"],
        [LD="$CC"
         LDFLAGS="-bundle $LDFLAGS"],
        [AC_MSG_ERROR([Only know compiler flags for gcc on this platform])])
    ;;
*-hpux*)
    AS_IF([test "$GCC" = "yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LD="$CC"
         LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"],
        [CFLAGS="+z $CFLAGS"
         LD="ld"
         LDFLAGS="+vshlibunsats -b $LDFLAGS"])
    ;;
x86_64-*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LD="$CC"
    LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $MAP $LDFLAGS"
    AS_IF([test x"$libdir" = x'${exec_prefix}/lib'],
        [libdir='${exec_prefix}/lib64'])
    ;;
*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LD="$CC"
    LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $MAP $LDFLAGS"
    ;;
*-solaris2*)
    AS_IF([test "$GCC" = "yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"],
        [CFLAGS="-KPIC $CFLAGS"
         LDFLAGS="-G -xldscope=symbolic $LDFLAGS"])
    LD="$CC"
    ;;
*)
    AS_IF([test "$GCC" = "yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LD="$CC"
         LDFLAGS="-fPIC -shared $LDFLAGS"],
        [AC_MSG_ERROR([Only know compiler flags for gcc on this platform])])
    ;;
esac
AC_SUBST([LD])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
