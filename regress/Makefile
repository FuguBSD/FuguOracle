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

# The regression tests. `make regress` builds kat and runs it. The
# vectors are committed as hex, so the run needs no Python and no
# network (TEST-KAT-2).
#
# The regress build defines REGRESS, so each draw of the seam comes
# from the file that FUGUORACLE_RANDOM names (SEC-RANDOM-2). The
# context blinding of SEC-RANDOM-3 draws outside the seam.

PROG=		kat
SRCS=		kat.c cipher.c

.PATH:		${.CURDIR}/..

LOCALBASE?=	/usr/local

CFLAGS+=	-Wall -Wextra -Werror -DREGRESS
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/.. -I${LOCALBASE}/include
LDFLAGS+=	-static -L${LOCALBASE}/lib
LDADD=		-lsecp256k1 -lcrypto
DPADD=		${LOCALBASE}/lib/libsecp256k1.a ${LIBCRYPTO}

.include <bsd.regress.mk>
