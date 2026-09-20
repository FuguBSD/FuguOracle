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

# The build of the source. OpenBSD make reads this file, and GNU make
# reads GNUmakefile for the document gates.
#
# The default target builds the two programs: fuguoracle, the program
# of PROG-CGI, and fuguoracle-keygen, the program of PROG-KEYGEN.
# Each one links the archive of the port and the archive of the base
# system, because the service runs inside the /var/www chroot
# (ARCH-STACK-3, ARCH-DEPS-4). The key generator runs outside the
# chroot, and one LDFLAGS line links both programs static.
#
# The key generator needs the shim of cipher.c beside its own source,
# because only that file holds a library call (ARCH-LAYOUT-1).
#
# MAN names the two manual pages of the two programs, in mdoc(7).
# bsd.prog.mk defaults MAN to one page of section 1 for each name of
# PROGS, so this line names the two pages of section 8 instead.
#
# This build defines no REGRESS, no PINS_DIR and no KEY_PATH, so it
# holds no test hook, and it names the two paths of PROG-CGI-4.
#
# `make -C regress regress` builds the known-answer tests, the unit
# tests and the tests of the operations. It links the archive of the
# port and the archive of the base system as well.

PROGS=			fuguoracle fuguoracle-keygen
SRCS_fuguoracle=	main.c http.c cipher.c oracle.c pindb.c
SRCS_fuguoracle-keygen=	keygen.c cipher.c
MAN=			fuguoracle.8 fuguoracle-keygen.8

LOCALBASE?=	/usr/local

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${LOCALBASE}/include
LDFLAGS+=	-static -L${LOCALBASE}/lib
LDADD=		-lsecp256k1 -lcrypto
DPADD=		${LOCALBASE}/lib/libsecp256k1.a ${LIBCRYPTO}

.include <bsd.prog.mk>
