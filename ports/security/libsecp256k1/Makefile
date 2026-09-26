COMMENT =	optimized C library for EC operations on curve secp256k1

GH_ACCOUNT =	bitcoin-core
GH_PROJECT =	secp256k1
GH_TAGNAME =	v0.8.0
PKGNAME =	lib${DISTNAME}

CATEGORIES =	security

HOMEPAGE =	https://github.com/bitcoin-core/secp256k1

MAINTAINER =	Dick Olsson <hi@senzilla.io>

# MIT
PERMIT_PACKAGE =	Yes

# The ports libtool builds the shared library, and it numbers it.
SHARED_LIBS =	secp256k1 0.0

# The release tarball holds no configure script.
CONFIGURE_STYLE =	autoreconf
AUTOCONF_VERSION =	2.71
AUTOMAKE_VERSION =	1.16

# The modules ecdh, recovery and extrakeys, and no other module. The
# package ships the static archive, the shared library, the headers
# and the pkg-config file.
CONFIGURE_ARGS =	--enable-module-ecdh \
			--enable-module-recovery \
			--enable-module-extrakeys \
			--disable-module-schnorrsig \
			--disable-module-ellswift \
			--disable-module-musig \
			--disable-module-silentpayments \
			--disable-benchmark

# make test runs the upstream suite: tests, noverify_tests and
# exhaustive_tests, through the check target of automake.

.include <bsd.port.mk>
