COMMENT =	blind PIN oracle and virtual secure element (pinserver v2)

GH_ACCOUNT =	FuguBSD
GH_PROJECT =	FuguOracle
GH_TAGNAME =	v0.1.0
PKGNAME =	${DISTNAME:L}

CATEGORIES =	security

HOMEPAGE =	https://github.com/FuguBSD/FuguOracle

MAINTAINER =	Dick Olsson <hi@senzilla.io>

# ISC
PERMIT_PACKAGE =	Yes

# The two programs link the static archive of the library, so the
# package needs no LIB_DEPENDS and no WANTLIB (PKG-ORACLE-5).
BUILD_DEPENDS =	security/libsecp256k1

# src/Makefile is the entry point of the C build (ARCH-BUILD-2). The
# build skips regress: bsd.regress.mk runs the tests on all, and the
# test target enters that directory (PKG-ORACLE-4).
WRKSRC =	${WRKDIST}/src
MAKE_FLAGS =	SKIPDIR=regress

do-test:
	cd ${WRKSRC}/regress && ${SETENV} ${MAKE_ENV} ${MAKE_PROGRAM} regress

# The CGI program sits inside the httpd(8) chroot (PKG-ORACLE-1).
do-install:
	${INSTALL_PROGRAM_DIR} ${WRKINST}${VARBASE}/www/cgi-bin
	${INSTALL_PROGRAM} ${WRKSRC}/fuguoracle/fuguoracle \
		${WRKINST}${VARBASE}/www/cgi-bin/fuguoracle
	${INSTALL_PROGRAM} ${WRKSRC}/fuguoracle-keygen/fuguoracle-keygen \
		${PREFIX}/sbin/fuguoracle-keygen
	${INSTALL_MAN} ${WRKSRC}/fuguoracle/fuguoracle.8 \
		${WRKSRC}/fuguoracle-keygen/fuguoracle-keygen.8 \
		${PREFIX}/man/man8
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/fuguoracle
	${INSTALL_DATA} ${FILESDIR}/httpd.conf \
		${PREFIX}/share/examples/fuguoracle

.include <bsd.port.mk>
