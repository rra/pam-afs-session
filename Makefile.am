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

AM_CPPFLAGS = $(KRB5_CPPFLAGS)

pamdir = $(libdir)/security
pam_LTLIBRARIES = pam_afs_session.la
pam_afs_session_la_SOURCES = logging.c options.c public.c tokens.c
pam_afs_session_la_LDFLAGS = -module -shared -avoid-version $(KRB5_LDFLAGS)
pam_afs_session_la_LIBADD = $(LTLIBOBJS) $(KRB5_LIBS)
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
