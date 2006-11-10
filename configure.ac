dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([pam-afs-session], [0.1], [rra@stanford.edu])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="$CFLAGS -Wall"
fi

dnl Figure out how we're going to get the kafs functions.  We only need
dnl k_hasafs, k_setpag, and k_unlog.  On Linux only, we can fall back to our
dnl internal implementation; otherwise, we have to have a library.
dnl
dnl For right now, we require libraries and an Os that can figure out their
dnl own transitive dependencies.  Eventually, this should be fixed.
AC_SEARCH_LIBS([k_hasafs], [kafs kopenafs], ,
    [case "$host" in
     *-linux*)
         AC_LIBOBJ([sys-linux])
         ;;
     *)
         AC_MSG_ERROR([No suitable kafs implementation found])
         ;;
     esac])
AC_CHECK_HEADERS([kafs.h], , [AC_CHECK_HEADERS([kopenafs.h])])

dnl If and only if we're on Linux, make sure that all the symbols in the
dnl module are resolved.  More platforms could be handled here.
case "$host" in
*-linux*)
    LDFLAGS="-Wl,-z,defs $LDFLAGS"
    ;;
esac

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
