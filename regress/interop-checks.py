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

"""interop-checks.py: the checks of the stack that the upstream suite lacks.

usage: interop-checks.py <url> <fixed url> <upstream url> <public key hex>

regress/interop puts this program into the OpenBSD guest, and it runs
the program there, in a directory that holds a 'pins' link to the
record directory of the service at <url>. The public key is the
static key of the service, as fuguoracle-keygen prints it, and the
two fixed servers hold the same key. The program builds each request
with the upstream client library, and each check is one test of
unittest, so the harness reads the report of this program as it reads
the report of the upstream suite.

The junk uniformity check (TEST-INTEROP-2) sends the four junk paths
of OPS-JUNK to the service at <url>: a missing record, a corrupt
record, a replay violation and a wrong PIN. It reads the real answer
of a correct PIN first, and each junk answer must hold the status,
the headers and the body length of that answer (OPS-JUNK-2). The
header set is every header of the answer but Date. httpd(8) writes
the clock into Date, and no other header carries a timestamp. The
program corrupts the record through the link, because no request can
corrupt one.

The failure table check (TEST-INTEROP-3) sends one request of each
failure class of PROTO-HTTP that a client can build to the service at
<url>, and it asserts the status of the table. httpd(8) answers two
classes before the program. It blocks an unknown path with 403
(DEPLOY-HTTPD-1), so the 404 of the program reaches no client, and
the check asserts 403. It answers a body above 4096 bytes with 413
(DEPLOY-HTTPD-3), the status of the program. The program answers
each other class. A decrypt failure and a padding failure need the
derived keys of a request, so no client can build them, and the check
omits them. The I/O failure is a directory at the record path, and
the persist failure is a record directory without write permission.
The program builds each one through the link, as root.

The byte identity check (TEST-ACCEPT-1, TEST-ACCEPT-3) sends one
request to the fixed instance of the service at <fixed url> and to
the upstream server at <upstream url>. Both read the fixed random
file, so the two 200 bodies must be identical, byte for byte, for
each row of the draw table of TEST-ACCEPT-2: set_pin, get_pin with
the correct PIN, get_pin with a wrong PIN and the third strike, and
get_pin with a missing record or a replay violation. Each get_pin
goes in the 97-byte form and in the 129-byte form (TEST-INTEROP-1).
A set_pin without entropy is a reject on both servers. The check
asserts that decision alone, because the error surface is out of
scope (D-12).
"""

import base64
import json
import os
import sys
import unittest

import requests

if len(sys.argv) != 5:
    sys.exit('usage: interop-checks.py <url> <fixed url> <upstream url> '
             '<public key hex>')
URL, FIXED_URL, UPSTREAM_URL = sys.argv[1:4]
PUBLIC_KEY = bytes.fromhex(sys.argv[4])

from blind_pin_server.client import PINClientECDH, PINClientECDHv2  # noqa: E402
from wallycore import sha256, ec_sig_from_bytes, EC_FLAG_ECDSA, \
    EC_FLAG_RECOVERABLE  # noqa: E402

# The one header that carries the clock of the answer.
CLOCK_HEADER = 'date'

# The record directory of the service at URL, through the link.
PINS = 'pins'


def body(envelope):
    """The request body of one envelope (PROTO-HTTP-7)."""
    data = base64.b64encode(bytes(envelope)).decode()
    return json.dumps({'data': data}).encode()


def post(url, path, data):
    """One POST request, and its answer."""
    return requests.post(url + path, data=data)


class Client:
    """One logical client: a static key, and a replay counter."""

    def __init__(self):
        self.private_key, self.public_key = \
            PINClientECDH.generate_ec_key_pair()
        self.counter = 0
        self.session = None

    def record(self):
        """The record path of this client (STORE-KEYS-3)."""
        return os.path.join(PINS, bytes(sha256(self.public_key)).hex() + '.pin')

    def envelope(self, pin_secret, entropy=b'', step=1, payload=None):
        """One request envelope, with the counter moved by step.

        A payload takes the place of the signed payload.
        """
        self.counter += step
        counter = self.counter.to_bytes(4, byteorder='little', signed=False)
        self.session = PINClientECDHv2(PUBLIC_KEY, counter)
        _, cke = self.session.get_key_exchange()
        if payload is None:
            message = sha256(cke + counter + pin_secret + entropy)
            sig = ec_sig_from_bytes(self.private_key, message,
                                    EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
            payload = pin_secret + entropy + sig
        return cke + counter + self.session.encrypt_request_payload(payload)

    def request(self, pin_secret, entropy=b'', step=1, payload=None):
        """The body of one request."""
        return body(self.envelope(pin_secret, entropy, step, payload))

    def key(self, answer):
        """The key of one 200 answer, with the keys of the last request."""
        envelope = base64.b64decode(answer.json()['data'])
        return bytes(self.session.decrypt_response_payload(envelope))


def corrupt(path):
    """Flip one byte of the authenticator of a record (STORE-RECORD)."""
    with open(path, 'r+b') as f:
        f.seek(1)
        byte = f.read(1)[0]
        f.seek(1)
        f.write(bytes([byte ^ 0xff]))


class Checks(unittest.TestCase):

    def set_pin(self, url, client, pin_secret):
        """One set_pin of a client at url, with fresh entropy."""
        answer = post(url, '/set_pin', client.request(pin_secret, os.urandom(32)))
        self.assertEqual(answer.status_code, 200, 'set_pin')
        return answer

    def status(self, want, answer, what):
        self.assertEqual(answer.status_code, want, what)

    # The junk uniformity (TEST-INTEROP-2)

    def answer(self, response):
        """The comparable part of one answer."""
        headers = {name: value for name, value in response.headers.items()
                   if name.lower() != CLOCK_HEADER}
        return response.status_code, headers, len(response.content)

    def test_junk_uniformity(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.set_pin(URL, client, pin_secret)
        real = post(URL, '/get_pin', client.request(pin_secret))
        self.status(200, real, 'the real answer')

        junk = {}
        junk['a wrong PIN'] = post(URL, '/get_pin',
                                   client.request(os.urandom(32)))
        junk['a replay violation'] = post(URL, '/get_pin',
                                          client.request(pin_secret, step=0))
        junk['a missing record'] = post(URL, '/get_pin',
                                        Client().request(pin_secret))
        corrupt(client.record())
        junk['a corrupt record'] = post(URL, '/get_pin',
                                        client.request(pin_secret))

        want = self.answer(real)
        for path, answer in junk.items():
            self.assertEqual(self.answer(answer), want, path)

    # The failure table (TEST-INTEROP-3)

    def test_failure_unknown_path(self):
        # httpd(8) blocks the path before the program (DEPLOY-HTTPD-1).
        answer = post(URL, '/nope', Client().request(os.urandom(32)))
        self.status(403, answer, 'an unknown path')

    def test_failure_wrong_method(self):
        self.status(405, requests.get(URL + '/get_pin'), 'GET /get_pin')
        self.status(405, requests.post(URL + '/'), 'POST /')

    def test_failure_oversized_body(self):
        # httpd(8) answers before the program (DEPLOY-HTTPD-3).
        data = b'{"data": "' + b'A' * 4085 + b'"}'
        self.assertEqual(len(data), 4097)
        self.status(413, post(URL, '/set_pin', data), 'a body of 4097 bytes')

    def test_failure_malformed_json(self):
        self.status(400, post(URL, '/get_pin', b'{"data": '), 'malformed JSON')

    def test_failure_bad_base64(self):
        self.status(400, post(URL, '/get_pin', b'{"data": "!!!!"}'),
                    'bad base64')

    def test_failure_length_violation(self):
        self.status(400, post(URL, '/get_pin', body(os.urandom(16))),
                    'an envelope of 16 bytes')

    def test_failure_bad_mac(self):
        envelope = bytearray(Client().envelope(os.urandom(32)))
        envelope[-1] ^= 0xff
        self.status(500, post(URL, '/get_pin', body(envelope)), 'a bad MAC')

    def test_failure_payload_length(self):
        data = Client().request(b'', payload=bytes(64))
        self.status(500, post(URL, '/get_pin', data), 'a payload of 64 bytes')

    def test_failure_signature_recovery(self):
        # A header byte of the libwally form, then r and s above the
        # order of the curve (PROTO-PAYLOAD-2).
        payload = os.urandom(32) + bytes([31]) + b'\xff' * 64
        data = Client().request(b'', payload=payload)
        self.status(500, post(URL, '/get_pin', data), 'a signature of ones')

    def test_failure_set_pin_without_entropy(self):
        data = Client().request(os.urandom(32))
        self.status(500, post(URL, '/set_pin', data), 'the 97-byte form')

    def test_failure_set_pin_corrupt_record(self):
        client = Client()
        self.set_pin(URL, client, os.urandom(32))
        corrupt(client.record())
        data = client.request(os.urandom(32), os.urandom(32))
        self.status(500, post(URL, '/set_pin', data), 'a corrupt record')

    def test_failure_set_pin_replay(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.set_pin(URL, client, pin_secret)
        self.status(200, post(URL, '/get_pin', client.request(pin_secret)),
                    'get_pin')
        data = client.request(pin_secret, os.urandom(32), step=0)
        self.status(500, post(URL, '/set_pin', data), 'an equal counter')

    def test_failure_io(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.set_pin(URL, client, pin_secret)
        os.remove(client.record())
        os.mkdir(client.record())
        try:
            answer = post(URL, '/get_pin', client.request(pin_secret))
        finally:
            os.rmdir(client.record())
        self.status(500, answer, 'a directory at the record path')

    def test_failure_persist(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.set_pin(URL, client, pin_secret)
        os.chmod(PINS, 0o500)
        try:
            answer = post(URL, '/get_pin', client.request(pin_secret))
        finally:
            os.chmod(PINS, 0o700)
        self.status(500, answer, 'a record directory without write permission')

    # The byte identity (TEST-ACCEPT-1, TEST-ACCEPT-3)

    def same(self, path, data, what):
        """One request to both fixed servers, and the identical answer."""
        fixed = post(FIXED_URL, path, data)
        upstream = post(UPSTREAM_URL, path, data)
        self.assertEqual((fixed.status_code, upstream.status_code),
                         (200, 200), what)
        self.assertEqual(fixed.content, upstream.content, what)
        return fixed

    def test_identity_set_pin(self):
        client = Client()
        self.same('/set_pin', client.request(os.urandom(32), os.urandom(32)),
                  'set_pin')

    def test_identity_get_pin_correct(self):
        client = Client()
        pin_secret = os.urandom(32)
        answer = self.same('/set_pin',
                           client.request(pin_secret, os.urandom(32)),
                           'set_pin')
        key = client.key(answer)
        for entropy in b'', os.urandom(32):
            answer = self.same('/get_pin', client.request(pin_secret, entropy),
                               'get_pin with the correct PIN')
            self.assertEqual(client.key(answer), key)

    def test_identity_get_pin_wrong(self):
        client = Client()
        self.same('/set_pin', client.request(os.urandom(32), os.urandom(32)),
                  'set_pin')
        for entropy in b'', os.urandom(32):
            self.same('/get_pin', client.request(os.urandom(32), entropy),
                      'get_pin with a wrong PIN')

    def test_identity_third_strike(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.same('/set_pin', client.request(pin_secret, os.urandom(32)),
                  'set_pin')
        for strike in 1, 2, 3:
            self.same('/get_pin', client.request(os.urandom(32)),
                      f'strike {strike}')
        self.same('/get_pin', client.request(pin_secret),
                  'get_pin after the wipe')

    def test_identity_missing_record(self):
        client = Client()
        for entropy in b'', os.urandom(32):
            self.same('/get_pin', client.request(os.urandom(32), entropy),
                      'get_pin with a missing record')

    def test_identity_replay(self):
        client = Client()
        pin_secret = os.urandom(32)
        self.same('/set_pin', client.request(pin_secret, os.urandom(32)),
                  'set_pin')
        self.same('/get_pin', client.request(pin_secret), 'get_pin')
        self.same('/get_pin', client.request(pin_secret, step=0),
                  'get_pin with an equal counter')
        self.same('/get_pin', client.request(pin_secret, step=-1),
                  'get_pin with a stale counter')

    def test_identity_set_pin_without_entropy(self):
        data = Client().request(os.urandom(32))
        self.assertNotEqual(post(FIXED_URL, '/set_pin', data).status_code, 200)
        self.assertNotEqual(post(UPSTREAM_URL, '/set_pin', data).status_code,
                            200)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
