# $Id$

include $(top_srcdir)/Makefile.am.common

if LIBEDIT
dir_editline = libedit
endif
if OTP
dir_otp = otp
endif
if DCE
dir_dce = kdfs
endif
if COM_ERR
dir_com_err = com_err
endif
if !SQLITE3
dir_sqlite = sqlite
endif
if MAINTAINER_MODE
dir_sqlite = sqlite
endif

SUBDIRS = \
	roken \
	base \
	vers \
	libedit \
	com_err \
	sl \
	wind \
	asn1 \
	hcrypto \
	ipc \
	hx509 \
	krb5 \
	ntlm \
	kafs \
	gssapi \
	hdb \
	kadm5

EXTRA_DIST = NTMakefile heimdal
