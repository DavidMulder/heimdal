# $Id$

include $(top_srcdir)/Makefile.am.common

if DARWIN
AM_LDFLAGS = -lobjc /System/Library/Frameworks/Foundation.framework/Foundation -lobjc /System/Library/Frameworks/Security.framework/Security
endif
AM_CPPFLAGS += $(INCLUDE_hcrypto) -I$(srcdir)/../lib/krb5 \
	$(INCLUDE_libintl) \
	-DHEIMDAL_LOCALEDIR='"$(localedir)"'

man_MANS = \
	kinit.1 \
	klist.1 \
	kdestroy.1 \
	kswitch.1 \
	kdigest.8 \
	kgetcred.1 \
	kimpersonate.8

bin_PROGRAMS = kinit kdestroy kgetcred kcc
libexec_PROGRAMS = kdigest kimpersonate

noinst_PROGRAMS = kverify kdecode_ticket generate-requests

if !NO_AFS
afs_lib = $(LIB_kafs)
endif

kinit_LDADD = \
    $(afs_lib) \
    $(top_builddir)/lib/wind/libwind.la \
    $(top_builddir)/lib/krb5/libkrb5.la \
    $(top_builddir)/lib/ntlm/libheimntlm.la \
    $(LIB_hcrypto) \
    $(top_builddir)/lib/asn1/libasn1.la \
    $(LIB_libintl) \
    $(LIB_roken)

kdestroy_LDADD	= $(kinit_LDADD)

kimpersonate_LDADD = $(kinit_LDADD)

kcc_LDADD = \
	$(top_builddir)/lib/sl/libsl.la \
	$(kinit_LDADD) \
	$(LIB_readline)

dist_kcc_SOURCES = kcc.c klist.c kswitch.c copy_cred_cache.c
nodist_kcc_SOURCES = kcc-commands.c

$(kcc_OBJECTS): kcc-commands.h

dist_kdigest_SOURCES = kdigest.c
nodist_kdigest_SOURCES = kdigest-commands.c

kdigest_LDADD = \
    $(top_builddir)/lib/ntlm/libheimntlm.la \
    $(top_builddir)/lib/wind/libwind.la \
    $(top_builddir)/lib/krb5/libkrb5.la \
    $(LIB_hcrypto) \
    $(top_builddir)/lib/asn1/libasn1.la \
    $(top_builddir)/lib/sl/libsl.la \
    $(LIB_roken)

$(kdigest_OBJECTS): kdigest-commands.h

CLEANFILES = \
	kdigest-commands.h kdigest-commands.c \
	kcc-commands.h kcc-commands.c

kdigest-commands.c kdigest-commands.h: kdigest-commands.in
	$(SLC) $(srcdir)/kdigest-commands.in

kcc-commands.c kcc-commands.h: kcc-commands.in
	$(SLC) $(srcdir)/kcc-commands.in

LDADD = \
    $(top_builddir)/lib/wind/libwind.la \
    $(top_builddir)/lib/krb5/libkrb5.la \
    $(LIB_hcrypto) \
    $(top_builddir)/lib/asn1/libasn1.la \
    $(LIB_roken)

EXTRA_DIST = NTMakefile $(man_MANS) \
	kcc-version.rc \
	kdestroy-version.rc \
	kdigest-version.rc \
	kgetcred-version.rc \
	kimpersonate-version.rc \
	kinit-version.rc \
	kuser_locl.h kcc-commands.in kdigest-commands.in copy_cred_cache.1

