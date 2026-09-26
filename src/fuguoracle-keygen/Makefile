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


# fuguoracle-keygen, the program of PROG-KEYGEN. This directory
# holds the manual page and no C source: keygen.c sits flat one
# directory up, and .PATH finds it there (ARCH-BUILD-1,
# ARCH-BUILD-2).
#
# The key generator needs the shim of cipher.c beside its own
# source, because only that file holds a library call
# (ARCH-LAYOUT-1). The archive of lib holds that shim, and the link
# takes the one object of it that keygen.c reaches.
#
# The key generator runs outside the /var/www chroot, and it links
# static as well: one link model serves both programs, and cgi.sh
# proves the link of both with ldd(1) (ARCH-STACK-3, ARCH-DEPS-4).
#
# The lookup of the archive tests the obj directory of lib. make obj
# puts the archive there, and a tree without make obj holds the
# archive in lib. This file writes the literal name obj, because no
# mk file has set ${__objdir} at that line.
#
# bsd.prog.mk defaults MAN to one page of section 1 for PROG, so
# MAN names the page of section 8 instead, in mdoc(7).

PROG=		fuguoracle-keygen
SRCS=		keygen.c
MAN=		fuguoracle-keygen.8

.PATH:		${.CURDIR}/..

LOCALBASE?=	/usr/local
LIBFUGUORACLE=	${.CURDIR}/../lib

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..

.if exists(${LIBFUGUORACLE}/obj)
LDADD+=		-L${LIBFUGUORACLE}/obj -lfuguoracle
DPADD+=		${LIBFUGUORACLE}/obj/libfuguoracle.a
.else
LDADD+=		-L${LIBFUGUORACLE} -lfuguoracle
DPADD+=		${LIBFUGUORACLE}/libfuguoracle.a
.endif

LDFLAGS+=	-static
LDADD+=		-L${LOCALBASE}/lib -lsecp256k1 -lcrypto
DPADD+=		${LOCALBASE}/lib/libsecp256k1.a ${LIBCRYPTO}

.include <bsd.prog.mk>
