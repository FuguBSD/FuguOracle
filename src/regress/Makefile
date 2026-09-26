#
# Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# The regression tests. `make regress` builds kat, unit, ops and cgi,
# and it runs each of them. The vectors are committed as hex, so the
# run needs no Python and no network (TEST-KAT-2).
#
# This directory compiles each source that it tests from the flat
# sources one directory up, through .PATH, and it links no archive:
# the archive of lib holds no test hook (ARCH-BUILD-3).
#
# The regress build defines REGRESS, so each draw of the seam comes
# from the file that FUGUORACLE_RANDOM names (SEC-RANDOM-2). The
# context blinding of SEC-RANDOM-3 draws outside the seam. The
# regress build also holds the record store hook, which gives a
# test control at one step of a store and of a wipe
# (ARCH-LAYOUT-5).
#
# The unit tests and the tests of the operations write records, so
# this build names a record directory of the regress tree. The cgi
# program reads a static key, so this build names a key file of the
# regress tree as well. Each path stays a compile-time constant
# (D-06). The interop harness builds cgi for a second instance inside
# the httpd chroot, so PINS_DIR and KEY_PATH take a value from the
# command line as well.
#
# cgi holds the source of the service program, and cgi.sh drives it
# with the CGI variables in the environment (PROG-CGI-1). A bare run
# of that program answers one request and it tests nothing, so
# REGRESS_TARGETS names run-cgi in place of the default target of
# the program.
#
# keygen.sh tests the key generator, and src/fuguoracle-keygen builds
# that program. The key file and the owner of PROG-KEYGEN-2 hold no
# build flag, so the program writes /var/www and it reads the passwd
# entry of _fuguoracle. run-keygen therefore names the program of that
# directory, and the test needs root. A run without root reports the
# skip, and it passes.

PROGS=		kat unit ops cgi
SRCS_kat=	kat.c cipher.c
SRCS_unit=	unit.c pindb.c cipher.c
SRCS_ops=	ops.c oracle.c pindb.c cipher.c
SRCS_cgi=	main.c http.c oracle.c pindb.c cipher.c

.PATH:		${.CURDIR}/..

LOCALBASE?=	/usr/local

CFLAGS+=	-Wall -Wextra -Werror -DREGRESS
PINS_DIR?=	${.OBJDIR}/pins
KEY_PATH?=	${.OBJDIR}/private.key

CFLAGS+=	-DPINS_DIR='"${PINS_DIR}"'
CFLAGS+=	-DKEY_PATH='"${KEY_PATH}"'
# Two include directories reach the headers of a test. The first one
# holds the interfaces of the flat sources, and the second one holds
# the vectors of the host harness, as vectors/vectors.h
# (ARCH-BUILD-5). cgi.sh reads the same header.
CFLAGS+=	-I${.CURDIR}/.. -I${.CURDIR}/../../tests
CFLAGS+=	-I${LOCALBASE}/include
LDFLAGS+=	-static -L${LOCALBASE}/lib
LDADD=		-lsecp256k1 -lcrypto
DPADD=		${LOCALBASE}/lib/libsecp256k1.a ${LIBCRYPTO}
CLEANFILES+=	pins/* pins/.random cgi.work/* keygen.work/* \
		private.key unit.random.* ops.random.*

REGRESS_TARGETS=	run-regress-kat run-regress-unit run-regress-ops \
			run-cgi run-keygen

run-cgi: cgi
	sh ${.CURDIR}/cgi.sh ${.OBJDIR}/cgi ${.OBJDIR}

# The key generator of src/fuguoracle-keygen. make obj puts the
# program in obj, and a tree without make obj holds it in the
# directory. This file writes the literal name obj, because no mk
# file has set ${__objdir} at that line.
KEYGEN_DIR=	${.CURDIR}/../fuguoracle-keygen
.if exists(${KEYGEN_DIR}/obj)
KEYGEN=		${KEYGEN_DIR}/obj/fuguoracle-keygen
.else
KEYGEN=		${KEYGEN_DIR}/fuguoracle-keygen
.endif

run-keygen:
	sh ${.CURDIR}/keygen.sh ${KEYGEN} ${.OBJDIR}

.PHONY: run-cgi run-keygen

.include <bsd.regress.mk>
