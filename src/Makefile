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
# reads GNUmakefile of the repository root for the document gates
# (ARCH-BUILD-4).
#
# The C sources sit flat in this directory, and the test sources sit
# in regress. lib builds the archive of the flat sources, fuguoracle
# builds the program of PROG-CGI from that archive, and
# fuguoracle-keygen builds the program of PROG-KEYGEN from it
# (ARCH-BUILD-1). regress compiles the flat sources a second time,
# with the test hooks on, so the archive that the service links
# holds none of them (ARCH-BUILD-3). The layout follows usr.bin/ssh
# of the OpenBSD tree.
#
# Each program gets a directory of its own with its manual page, and
# it builds there through bsd.prog.mk (ARCH-BUILD-2).
#
# The regress loop runs cgi.sh and keygen.sh, and the two scripts
# run the two programs, so the loop must run after the build loop.
# bsd.subdir.mk declares regress with the double-colon operator, and
# this line must use the same operator.
#
# SUBDIR holds the build order of the loop: lib builds the archive
# that each program links, and regress comes last.

regress:: all

SUBDIR=	lib fuguoracle fuguoracle-keygen regress

.include <bsd.subdir.mk>
