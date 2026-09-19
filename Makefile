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
# The tree holds the shim, the record store and the state machine, so
# the default target compiles them. The programs of PROG-CGI and
# PROG-KEYGEN add main.c, http.c and keygen.c, and this file then
# links them. They link static, because the service runs inside the
# /var/www chroot (ARCH-STACK-3, ARCH-DEPS-4).
#
# This build defines no REGRESS and no PINS_DIR, so it holds no test
# hook and it names the record directory of PROG-CGI-4.
#
# `make -C regress regress` builds the known-answer tests, the unit
# tests and the tests of the operations. It links the archive of the
# port and the archive of the base system today.

LOCALBASE?=	/usr/local

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${LOCALBASE}/include

OBJS=		cipher.o oracle.o pindb.o

all: ${OBJS}

cipher.o: cipher.c cipher.h
oracle.o: oracle.c oracle.h pindb.h cipher.h
pindb.o: pindb.c pindb.h cipher.h

clean:
	rm -f ${OBJS}
