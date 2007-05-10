dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ([2.57])
AC_INIT([pam-afs-session], [1.4], [rra@stanford.edu])

m4_include([m4/krb5.m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
AC_HEADER_STDC

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

dnl Let the user tell us where their AFS headers are.
AC_ARG_WITH([afs-headers],
    AC_HELP_STRING([--with-afs-headers=PATH],
        [Path to OpenAFS headers (for syscall number)]),
    [if test x"$withval" != xno ; then
        CPPFLAGS="-I$withval $CPPFLAGS"
    fi])

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl If --enable-reduced-depends is used, we don't try to chase Kerberos
dnl library dependencies for libkafs and assume that the dynamic loader
dnl can cope.
reduced_depends=false
AC_ARG_ENABLE([reduced-depends],
    AC_HELP_STRING([--enable-reduced-depends],
        [Try to minimize shared library dependencies]),
    [if test x"$enableval" = xyes ; then
        reduced_depends=true
    fi])

dnl We can optionally build with Kerberos libraries so that we can use
dnl Kerberos calls to get configuration information.
KRBROOT=
kerberos=false
AC_ARG_WITH([kerberos],
    AC_HELP_STRING([--with-kerberos@<:@=DIR@:>@],
        [Compile with Kerberos v5 for configuration]),
    [if test x"$withval" != xno ; then
        kerberos=true
        if test x"$withval" != xyes ; then
            KRBROOT="$withval"
        fi
        AC_DEFINE([HAVE_KERBEROS], 1, [Define to enable Kerberos features.])
     fi])
if test x"$kerberos" = xtrue ; then
    RRA_LIB_KRB5([true])
fi

dnl Figure out how we're going to get the kafs functions.  We only need
dnl k_hasafs, k_setpag, and k_unlog.  On Linux only, we can fall back to our
dnl internal implementation; otherwise, we have to have a library.
dnl
dnl libkafs may require the Kerberos libraries, so we have to do this annoying
dnl dance where we check for them first just in case we need them.  The first
dnl parameter says whether to fail if Kerberos isn't found.
libkafs=true
AC_ARG_WITH([libkafs],
    AC_HELP_STRING([--without-libkafs],
        [Always use internal AFS syscall code]),
    [if test x"$withval" = xno ; then
        libkafs=false
     fi])
if test x"$libkafs" != xfalse ; then
    save_LIBS=$LIBS
    if test x"$kerberos" != xtrue ; then
        if test x"$reduced_depends" != xtrue ; then
            RRA_LIB_KRB5([false])
        fi
    fi
    AC_CHECK_LIB([kafs], [k_hasafs],
        [LIBS="-lkafs $LIBS"
         AC_CHECK_HEADERS([kafs.h])],
        [LIBS=$save_LIBS
         AC_CHECK_LIB([kopenafs], [k_hasafs],
            [LIBS="-lkopenafs $LIBS"
             AC_CHECK_HEADERS([kopenafs.h])],
            [libkafs=false])])
fi
if test x"$libkafs" = xtrue ; then
    if test x"$kerberos" = xtrue ; then
        AC_CHECK_FUNCS([krb5_afslog])
    fi
else
    case "$host" in
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
    esac
fi

dnl Other portability checks.
LIBS="-lpam $LIBS"
AC_CHECK_FUNCS([pam_getenv pam_getenvlist])
AC_CHECK_HEADERS([sys/ioccom.h])
AC_TYPE_SIGNAL

dnl Mac OS X calls its PAM headers something different than everyone else.
AC_CHECK_HEADERS([security/pam_appl.h], ,
    [AC_CHECK_HEADERS([pam/pam_appl.h], ,
        [AC_MSG_ERROR([No PAM header files found])])])

dnl Needed to get a prototype for environ on Linux.
AC_DEFINE([_GNU_SOURCE], [1], [Define to 1 on Linux to get full prototypes.])

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.  Also, if and only if we're on Linux, make sure that all the
dnl symbols in the module are resolved.
dnl
dnl More platforms could be handled here.  Contributions welcome.
case "$host" in
*-darwin*)
    if test "$GCC" = "yes" ; then
        LD="$CC"
        LDFLAGS="-bundle $LDFLAGS"
    else
        AC_MSG_ERROR([Only know compiler flags for gcc on this platform])
    fi
    ;;
*-hpux*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="+z $CFLAGS"
        LD="ld"
        LDFLAGS="+vshlibunsats -b $LDFLAGS"
    fi
    ;;
*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LD="$CC"
    LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $LDFLAGS"
    ;;
*-solaris2*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="-KPIC $CFLAGS"
        LDFLAGS="-G -xldscope=symbolic $LDFLAGS"
    fi
    LD="$CC"
    ;;
*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LD="$CC"
        LDFLAGS="-fPIC -shared $LDFLAGS"
    else
        AC_MSG_ERROR([Only know compiler flags for gcc on this platform])
    fi
    ;;
esac
AC_SUBST([LD])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
