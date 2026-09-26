#!/usr/bin/env python3
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

"""interop-upstream.py: the upstream test suite against the stack.

usage: interop-upstream.py <url> <public key hex>

tests/interop puts this program into the OpenBSD guest, and it runs
the program there, in a directory that holds a 'pins' link to the
record directory of the service. The program runs the tests of the
upstream test suite that speak protocol v2 to a URL, against the
FuguOracle stack at that URL (TEST-INTEROP-1). The public key is the
static key of the service, as fuguoracle-keygen prints it.

The upstream suite starts a Flask app of its own in setUpClass, and it
holds no URL variable, so this program takes the suite as a base class
and points it at the URL. Its setUpClass starts no server, and its
tearDownClass stops none: it removes the records of the run alone.
The tests below run as upstream wrote them, except for the protocol
argument: each mixed test of the suite runs its v2 half only, because
the service implements no protocol v1 (D-02). test_client_entropy_v2
is the upstream test with v2 in the one place that hard-codes v1.
test_wrong_pin_twice_then_correct_v2 is not in the upstream suite:
TEST-INTEROP-1 needs it, and it uses the helpers of the suite alone.

The tests of the upstream suite that this program does not run:

- Every v1 test and v1 half: test_protocol_upgrade_downgrade,
  test_delayed_interaction_v1, test_cannot_reuse_client_session_v1,
  and the v1 halves of the mixed tests (D-02).
- test_rejects_bad_payload_not_json and test_rejects_on_bad_json: they
  assert status 500 for a malformed body, and the service answers 400
  before the envelope decrypts (D-12, the deviation table of
  spec/overview.md).
- test_get_index: it asserts status 404 for an unknown path, and
  httpd(8) blocks that path before the service sees it
  (DEPLOY-HTTPD-1).

The import of the upstream Flask app reads a private key file from the
working directory, so the program writes one. That key signs nothing
and reaches no wire: every request goes to the service at the URL.
"""

import os
import stat
import sys
import unittest
from hmac import compare_digest

if len(sys.argv) != 3:
    sys.exit('usage: interop-upstream.py <url> <public key hex>')
URL = sys.argv[1]
PUBLIC_KEY = bytes.fromhex(sys.argv[2])

fd = os.open('server_private_key.key', os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
             stat.S_IRUSR | stat.S_IWUSR)
with os.fdopen(fd, 'wb') as f:
    f.write(os.urandom(32))
with open('server_public_key.pub', 'wb') as f:
    f.write(PUBLIC_KEY)

from blind_pin_server.test import test_pinserver as upstream  # noqa: E402
from blind_pin_server.pindb import PINDb  # noqa: E402
from wallycore import AES_KEY_LEN_256  # noqa: E402


class OracleTest(upstream.PINServerTest):
    """The upstream suite, pointed at the stack."""

    @classmethod
    def setUpClass(cls):
        cls.static_server_public_key = PUBLIC_KEY
        cls.pinfiles = set()
        cls.pinserver_url = URL

    @classmethod
    def tearDownClass(cls):
        for f in cls.pinfiles:
            if PINDb.storage.exists(f):
                PINDb.storage.remove(f)

    def test_set_and_get_pin_v2(self):
        self._test_set_and_get_pin_impl(True)

    def test_bad_guesses_clears_pin_v2(self):
        self._test_bad_guesses_clears_pin_impl(True)

    def test_bad_pubkey_breaks_v2(self):
        self._test_bad_pubkey_breaks_impl(True)

    def test_two_users_with_same_pin_v2(self):
        self._test_two_users_with_same_pin_impl(True, True)

    def test_client_entropy_v2(self):
        priv_key, _, _ = self.new_static_client_keys()
        pin_secret = self.new_pin_secret()

        # Fails if setting the pin secret without passing client entropy
        with self.assertRaises(ValueError) as cm:
            self.set_pin(priv_key, pin_secret, b'', True)

        self.assertEqual('500', str(cm.exception.args[0]))

        # Set pin with client entropy - fine
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), True)

        # Get call works with or without entropy (it's ignored in any case)
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy(), True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

    def test_wrong_pin_twice_then_correct_v2(self):
        priv_key, _, pinfile = self.new_static_client_keys()
        pin_secret = self.new_pin_secret()

        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), True)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # Two wrong guesses answer a junk key each, and the record stays
        for attempt in range(2):
            guesskey = self.get_pin(priv_key, self.new_pin_secret(), b'', True)
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # The correct pin answers the key, and it sets the count back
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Two more wrong guesses reach no third strike after the reset
        for attempt in range(2):
            guesskey = self.get_pin(priv_key, self.new_pin_secret(), b'', True)
            self.assertFalse(compare_digest(aeskey_s, guesskey))
        self.assertTrue(PINDb.storage.exists(pinfile))
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))


TESTS = [
    'test_get_root_empty',
    'test_set_and_get_pin_v2',
    'test_wrong_pin_twice_then_correct_v2',
    'test_bad_guesses_clears_pin_v2',
    'test_bad_pubkey_breaks_v2',
    'test_two_users_with_same_pin_v2',
    'test_client_entropy_v2',
    'test_cannot_reuse_client_session_v2',
    'test_set_pin_counter_v2',
]

if __name__ == '__main__':
    suite = unittest.TestSuite(OracleTest(name) for name in TESTS)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
