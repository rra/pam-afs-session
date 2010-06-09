# Automake makefile for pam-afs-session.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE autogen compat-aix.c examples/debian/common-account \
	examples/debian/common-auth examples/debian/common-session	 \
	examples/redhat/system-auth examples/solaris/pam.conf		 \
	pam_afs_session.map pam_afs_session.pod

# The following library order matters for annoying reasons.  libafsauthent
# contains its own com_err implementation, which we do not want to pick up.
#
# If pam_afs_session calls com_err functions directly, configure adds
# -lcom_err to the link line explicitly.  In that case, we want to link with
# the AFS libraries last, after -lcom_err, so that we don't use its com_err
# implementation.  If pam_afs_session doesn't call com_err functions, we
# want to link with the AFS libraries first, since otherwise in the
# --enable-reduced-depends case the linker may try to resolve the com_err
# symbols in libkrb5 from the AFS libraries.
if KRB5_USES_COM_ERR
    DEPEND_LIBS = $(KRB5_LIBS) $(KAFS_LIBS)
else
    DEPEND_LIBS = $(KAFS_LIBS) $(KRB5_LIBS)
endif

AM_CPPFLAGS = $(KRB5_CPPFLAGS)

noinst_LTLIBRARIES = pam-util/libpamutil.la
pam_util_libpamutil_la_SOURCES = pam-util/args.c pam-util/args.h	\
	pam-util/logging.c pam-util/logging.h pam-util/options.c	\
	pam-util/options.h pam-util/vector.c pam-util/vector.h

if NEED_KAFS
    noinst_LTLIBRARIES += kafs/libkafs.la
    EXTRA_kafs_libkafs_la_SOURCES = kafs/sys-linux.c kafs/sys-syscall.c
    kafs_libkafs_la_SOURCES = kafs/kafs.c kafs/kafs.h portable/macros.h	\
	portable/stdbool.h portable/system.h
    kafs_libkafs_la_CPPFLAGS = $(KAFS_CPPFLAGS)
    LIBKAFS = kafs/libkafs.la
endif

pamdir = $(libdir)/security
pam_LTLIBRARIES = pam_afs_session.la
pam_afs_session_la_SOURCES = logging.c options.c public.c tokens.c
pam_afs_session_la_LDFLAGS = -module -shared -avoid-version $(KRB5_LDFLAGS)
pam_afs_session_la_LIBADD = $(LTLIBOBJS) $(LIBKAFS) pam-util/libpamutil.la \
	$(DEPEND_LIBS)
dist_man_MANS = pam_afs_session.5

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		 \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp	 \
	build-aux/install-sh build-aux/ltmain.sh build-aux/missing	 \
	config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
	m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4 pam_afs_session.5

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
