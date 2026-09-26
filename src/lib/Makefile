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


# libfuguoracle.a, the archive of the flat sources one directory up.
# .PATH finds them there, and SRCS names each one. Each program
# directory links this archive, so each source compiles once in the
# production build (ARCH-BUILD-1). The regress directory compiles
# the same sources again, with the test hooks on, and it links no
# archive (ARCH-BUILD-3).
#
# This build defines no REGRESS, no PINS_DIR and no KEY_PATH, so the
# archive holds no test hook, and pindb.c reads the record directory
# of PROG-CGI-4 from pindb.h.
#
# cipher.c alone reads the headers of libsecp256k1 and libcrypto
# (ARCH-LAYOUT-1). libsecp256k1 comes from the ports tree, under
# LOCALBASE, and each program directory links the static archive of
# it (ARCH-DEPS-4).
#
# The archive stays inside the tree. It installs nothing, and it
# builds no shared object and no profiling object.

.PATH:		${.CURDIR}/..

LIB=		fuguoracle
SRCS=		cipher.c http.c oracle.c pindb.c

LOCALBASE?=	/usr/local

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${LOCALBASE}/include

NOPIC=		yes
NOPROFILE=	yes

install:
	@true

.include <bsd.lib.mk>
