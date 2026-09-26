# mk/local.mk: the consumer hook of this repository (MK-LOCAL).
# sync never touches this file.

# The full test tier set of make test
TEST_GLOBS	= t/fuguoracle/*.t t/ci/*.t

# The interop harness (TEST-INTEROP). It needs an OpenBSD guest, the
# fuguvm tool, and a checkout of the upstream server, so no
# CHECK_TARGETS line and no TEST_GLOBS entry names it, and make check
# never runs it. tests/interop states the environment that the
# operator gives it.
INTEROP		= tests/interop

interop:
	@$(INTEROP)

.PHONY: interop
