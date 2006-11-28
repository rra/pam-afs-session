dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([pam-afs-session], [0.2], [rra@stanford.edu])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST

dnl Determine the path to aklog.  If we can't figure it out, the user will
dnl have to set program in the PAM options.
AC_ARG_WITH([aklog],
    AC_HELP_STRING([--with-aklog=PATH],
        [Path to aklog or other Kerberos v5 AFS token program]),
    [if test x"$withval" != xno ; then
        PATH_AKLOG=$withval
    fi],
    [AC_PATH_PROGS([PATH_AKLOG], [aklog])])
if test -n "$PATH_AKLOG" ; then
    AC_DEFINE_UNQUOTED([PATH_AKLOG], ["$PATH_AKLOG"],
        [Full path to aklog binary.])
fi

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl Figure out how we're going to get the kafs functions.  We only need
dnl k_hasafs, k_setpag, and k_unlog.  On Linux only, we can fall back to our
dnl internal implementation; otherwise, we have to have a library.
dnl
dnl For right now, we require libraries and an Os that can figure out their
dnl own transitive dependencies.  Eventually, this should be fixed.
AC_SEARCH_LIBS([k_hasafs], [kafs kopenafs],
    [AC_CHECK_HEADERS([kafs.h], , [AC_CHECK_HEADERS([kopenafs.h])])],
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

AC_CHECK_HEADERS([sys/ioccom.h])
AC_TYPE_SIGNAL

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.  Also, if and only if we're on Linux, make sure that all the
dnl symbols in the module are resolved.
dnl
dnl More platforms could be handled here.  Contributions welcome.
case "$host" in
*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LDFLAGS="-shared -Wl,-z,defs -Wl,-Bsymbolic $LDFLAGS"
    ;;
*-solaris2*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-shared -Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="-KPIC $CFLAGS"
        LDFLAGS="-G -xldscope=symbolic $LDFLAGS"
    fi
    ;;
*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-shared $LDFLAGS"
    else
        AC_MSG_ERROR([Only know compiler flags for gcc on this platform])
    fi
    ;;
esac

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
