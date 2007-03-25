dnl krb5.m4 -- Find the compiler and linker flags for Kerberos v5.
dnl $Id: krb5.m4 2417 2006-02-03 23:35:46Z rra $
dnl
dnl Finds the compiler and linker flags and adds them to CPPFLAGS and LIBS.
dnl Provides --with-kerberos and --enable-reduced-depends configure options to
dnl control how linking with Kerberos is done.  Uses krb5-config where
dnl available unless reduced dependencies is requested.  Provides the macro
dnl RRA_LIB_KRB5.

dnl Does the appropriate library checks for reduced-dependency krb5 linkage.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_REDUCED],
[AC_CHECK_LIB([krb5], [krb5_init_context], [KRB5_LIBS="-lkrb5"],
    [if test x"$1" = xtrue ; then
         AC_MSG_ERROR([cannot find usable Kerberos v5 library])
     fi])
AC_CHECK_LIB([com_err], [com_err], [KRB5_LIBS="$KRB5_LIBS -lcom_err"],
    [if test x"$1" = xtrue ; then
         AC_MSG_ERROR([cannot find usable com_err library])
     fi])])

dnl Does the appropriate library checks for krb5 linkage.  Note that we have
dnl to check for a different function the second time since the Heimdal and
dnl MIT libraries have the same name.
AC_DEFUN([_RRA_LIB_KRB5_KRB5],
[AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRB5_LIBS="-lkrb5 -lasn1 -lroken -lcrypto -lcom_err"],
    [KRB5EXTRA="-lk5crypto -lcom_err"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [KRB5EXTRA="$KRB5EXTRA -lkrb5support"],
        [AC_SEARCH_LIBS([pthread_setspecific], [pthreads pthread])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [KRB5EXTRA="$KRB5EXTRA -lkrb5support"])])
     AC_CHECK_LIB([krb5], [krb5_cc_default],
        [KRB5_LIBS="-lkrb5 $KRB5EXTRA"],
        [if test x"$1" = xtrue ; then
             AC_MSG_ERROR([cannot find usable Kerberos v5 library])
         fi],
        [$KRB5EXTRA])],
    [-lasn1 -lroken -lcrypto -lcom_err])])

dnl Additional checks for portability between MIT and Heimdal if krb5
dnl libraries were requested.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_EXTRA],
[AC_CHECK_HEADERS([et/com_err.h])
AC_CHECK_FUNCS([krb5_get_error_message krb5_free_error_message \
                krb5_get_err_text])])

dnl The main macro.  Normally, I would provide --with-kerberos here, but since
dnl building with Kerberos is generally optional, that flag is back in the
dnl main configure.ac and sets KRBROOT.  Takes a parameter which is true if we
dnl should fail if no Kerberos libraries are found and false otherwise.  Start
dnl with handling the reduced depends case.
AC_DEFUN([RRA_LIB_KRB5],
[if test x"$reduced_depends" = xtrue ; then
    if test x"$KRBROOT" != x ; then
        if test x"$KRBROOT" != x/usr ; then
            CPPFLAGS="$CPPFLAGS -I$KRBROOT/include"
        fi
        LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
    fi
    _RRA_LIB_KRB5_KRB5_REDUCED([$1])
fi

dnl Checking for the neworking libraries shouldn't be necessary for the
dnl krb5-config case, but apparently it is at least for MIT Kerberos 1.2.
dnl This will unfortunately mean multiple -lsocket -lnsl references when
dnl building with current versions of Kerberos, but this shouldn't cause
dnl any practical problems.
if test x"$reduced_depends" != xtrue ; then
    AC_SEARCH_LIBS([gethostbyname], [nsl])
    AC_SEARCH_LIBS([socket], [socket], ,
        [AC_CHECK_LIB([nsl], [socket],
            [LIBS="-lnsl -lsocket $LIBS"], , [-lsocket])])
    AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
    if test x"$KRBROOT" != x ; then
        if test -x "$KRBROOT/bin/krb5-config" ; then
            KRB5_CONFIG="$KRBROOT/bin/krb5-config"
        fi
    else
        AC_PATH_PROG([KRB5_CONFIG], [krb5-config])
    fi

    if test x"$KRB5_CONFIG" != x ; then
        AC_MSG_CHECKING([for krb5 support in krb5-config])
        if "$KRB5_CONFIG" | grep krb5 > /dev/null 2>&1 ; then
            AC_MSG_RESULT([yes])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags krb5`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs krb5`
        else
            AC_MSG_RESULT([no])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs`
        fi
        KRB5_CPPFLAGS=`echo "$KRB5_CPPFLAGS" | sed 's%-I/usr/include ?%%'`
    else
        if test x"$KRBROOT" != x ; then
            if test x"$KRBROOT" != x/usr ; then
                KRB5_CPPFLAGS="-I$KRBROOT/include"
            fi
            LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
        fi
        AC_SEARCH_LIBS([res_search], [resolv], ,
            [AC_SEARCH_LIBS([__res_search], [resolv])])
        AC_SEARCH_LIBS([crypt], [crypt])
        _RRA_LIB_KRB5_KRB5([$1])
    fi
    if test x"$KRB5_CPPFLAGS" != x ; then
        CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS"
    fi
fi

dnl Generate the final library list and put it into the standard variables.
LIBS="$KRB5_LIBS $LIBS"
CPPFLAGS=`echo "$CPPFLAGS" | sed 's/^  *//'`
LDFLAGS=`echo "$LDFLAGS" | sed 's/^  *//'`
_RRA_LIB_KRB5_KRB5_EXTRA
])
