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

"""Write vectors.h beside this file from libwally (TEST-KAT-1).

usage: python3 generate.py

The upstream server derives its wire values through libwally, so
libwally answers each question of the wire protocol. This script asks
those questions once, and it writes the answers as hex. The developer
runs it in a virtual environment that holds the wallycore package, and
commits the header. The regress suite then needs no Python and no
network (TEST-KAT-2).

Every input is the hash of an ASCII label, so two runs write the same
header. The script prints nothing when it succeeds.
"""

import os
import sys

import wallycore as wally

LICENSE = """\
/*
 * Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The known-answer vectors of the cipher shim (TEST-KAT-1).
 *
 * tests/vectors/generate.py writes this file from libwally. Do not
 * edit it. Every value is a hex string, and a counter or a parity
 * bit is a decimal number. Each request of the transcript holds both
 * sides, so a client implementation reads the same file.
 */"""

REQUEST_LABEL = b"blind_oracle_request"
RESPONSE_LABEL = b"blind_oracle_response"


def secret(label):
    """A deterministic 32-byte value from an ASCII label."""
    return wally.sha256(label.encode("ascii"))


def private_key(label):
    """A deterministic private key from an ASCII label."""
    key = secret(label)
    wally.ec_private_key_verify(key)
    return key


def public_key(private):
    """The compressed public key of a private key."""
    return wally.ec_public_key_from_private_key(private)


def le32(value):
    """A uint32 in little-endian byte order."""
    return value.to_bytes(4, "little")


def merkle_root(cke, counter):
    """The tweak input m of PROTO-TWEAK-1."""
    return wally.sha256(wally.hmac_sha256(cke, le32(counter)))


def tweak(static_private, cke, counter):
    """The request private key d' of PROTO-TWEAK-2."""
    return wally.ec_private_key_bip341_tweak(
        static_private, merkle_root(cke, counter), 0
    )


def tweak_point(static_private, cke, counter):
    """The request public key Q' of PROTO-TWEAK-4.

    The answer is the x-only key and the parity bit of its Y
    coordinate. A client tweaks the static public key P, and the
    server tweaks the private key d. The two answers name one point,
    and this function proves it before it writes the vector.
    """
    point = wally.ec_public_key_bip341_tweak(
        public_key(static_private), merkle_root(cke, counter), 0
    )
    assert point == public_key(tweak(static_private, cke, counter))
    return point[1:], bool(point[0] & 1)


def split(private, cke, label):
    """The enc_key and the mac_key of PROTO-ENCRYPT-2."""
    keys = wally.hmac_sha512(wally.ecdh(cke, private), label)
    return keys[:32], keys[32:]


def seal(private, cke, label, iv, payload):
    """The envelope IV, ciphertext and tag of PROTO-ENCRYPT-4."""
    return wally.aes_cbc_with_ecdh_key(
        private, iv, payload, cke, label, wally.AES_FLAG_ENCRYPT
    )


def sign(private, message):
    """A recoverable signature of a message hash (PROTO-PAYLOAD-2)."""
    return wally.ec_sig_from_bytes(
        private, message, wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE
    )


def make_request(static, client, name, counter, pin_secret, entropy):
    """One request of the transcript, as a table of values.

    The payload takes the 129-byte form with entropy, and the 97-byte
    form without it (PROTO-PAYLOAD-1). The signed message hash covers
    cke, the counter, pin_secret and entropy (PROTO-PAYLOAD-3).
    """
    cke_private = private_key("FuguOracle KAT %s ephemeral key" % name)
    cke = public_key(cke_private)
    private = tweak(static, cke, counter)
    point, parity = tweak_point(static, cke, counter)
    message = wally.sha256(cke + le32(counter) + pin_secret + entropy)
    payload = pin_secret + entropy + sign(client, message)
    iv = secret("FuguOracle KAT %s iv" % name)[:16]
    enc = seal(private, cke, REQUEST_LABEL, iv, payload)
    return {
        "CKE_PRIV": cke_private,
        "CKE": cke,
        "COUNTER": counter,
        "M": merkle_root(cke, counter),
        "DPRIME": private,
        "QPRIME": point,
        "QPRIME_PARITY": parity,
        "MSGHASH": message,
        "PAYLOAD": payload,
        "IV": iv,
        "ENC": enc,
        "ENVELOPE": cke + le32(counter) + enc,
    }


def rows(prefix, table):
    """The header rows of one request table."""
    order = (
        "CKE_PRIV CKE COUNTER M DPRIME QPRIME QPRIME_PARITY "
        "MSGHASH PAYLOAD IV ENC ENVELOPE"
    ).split()
    return [("V_%s_%s" % (prefix, name), table[name]) for name in order]


def vectors():
    """Every vector of the header, in reading order."""
    static = private_key("FuguOracle KAT static key")

    # The unit vectors of the tweak and of the key split. The counter
    # holds four different bytes, so a byte order error fails here.
    cke_private = private_key("FuguOracle KAT ephemeral key")
    cke = public_key(cke_private)
    counter = 0x04030201
    private = tweak(static, cke, counter)
    point, parity = tweak_point(static, cke, counter)
    request_enc, request_mac = split(private, cke, REQUEST_LABEL)
    response_enc, response_mac = split(private, cke, RESPONSE_LABEL)

    # The transcript of one client key: a set_pin request, then a
    # get_pin request with a higher replay counter.
    client = private_key("FuguOracle KAT client key")
    pin_secret = secret("FuguOracle KAT pin secret")
    entropy = secret("FuguOracle KAT client entropy")
    put = make_request(static, client, "set", 1, pin_secret, entropy)
    got = make_request(static, client, "get", 2, pin_secret, b"")

    # The answer to that get_pin request: the share of the record,
    # under the response label of the same shared secret.
    share = secret("FuguOracle KAT key share")
    response = wally.hmac_sha256(share, pin_secret)
    response_iv = secret("FuguOracle KAT response iv")[:16]
    response_envelope = seal(
        got["DPRIME"], got["CKE"], RESPONSE_LABEL, response_iv, response
    )

    # The record of that client: the 69-byte plaintext of STORE-RECORD
    # and the 96-byte enc field that holds it.
    record_key = secret("FuguOracle KAT storage key")
    record_iv = secret("FuguOracle KAT record iv")[:16]
    record = wally.sha256(pin_secret) + share + bytes([1]) + le32(2)
    record_enc = record_iv + wally.aes_cbc(
        record_key, record_iv, record, wally.AES_FLAG_ENCRYPT
    )

    # The inputs of the two hash functions of the shim.
    message = b"FuguOracle known-answer message"
    hmac_key = secret("FuguOracle KAT hmac key")

    # The fixed random source of the seam, in draw order: the envelope
    # seal, the response seal, the record seal, then the seam test.
    seam = secret("FuguOracle KAT seam tail")[:16]
    source = got["IV"] + response_iv + record_iv + seam

    entries = [
        ("The static server keypair of PROTO-TWEAK.", None),
        ("V_STATIC_PRIV", static),
        ("V_STATIC_PUB", public_key(static)),
        ("One tweak of the static key, and the split of its shared secret.", None),
        ("V_TWEAK_CKE_PRIV", cke_private),
        ("V_TWEAK_CKE", cke),
        ("V_TWEAK_COUNTER", counter),
        ("V_TWEAK_M", merkle_root(cke, counter)),
        ("V_TWEAK_DPRIME", private),
        ("V_TWEAK_QPRIME", point),
        ("V_TWEAK_QPRIME_PARITY", parity),
        ("V_TWEAK_SHARED", wally.ecdh(cke, private)),
        ("V_TWEAK_REQUEST_ENC_KEY", request_enc),
        ("V_TWEAK_REQUEST_MAC_KEY", request_mac),
        ("V_TWEAK_RESPONSE_ENC_KEY", response_enc),
        ("V_TWEAK_RESPONSE_MAC_KEY", response_mac),
        ("The client of the transcript, and the two client secrets.", None),
        ("V_CLIENT_PRIV", client),
        ("V_CLIENT_PUB", public_key(client)),
        ("V_PIN_SECRET", pin_secret),
        ("V_ENTROPY", entropy),
        ("The set_pin request: the 129-byte payload form.", None),
    ]
    entries += rows("SET", put)
    entries += [("The get_pin request: the 97-byte payload form.", None)]
    entries += rows("GET", got)
    entries += [
        ("The answer to that get_pin request.", None),
        ("V_RESPONSE_PAYLOAD", response),
        ("V_RESPONSE_IV", response_iv),
        ("V_RESPONSE_ENC", response_envelope),
        ("The record of that client, in the 69-byte layout.", None),
        ("V_RECORD_KEY", record_key),
        ("V_RECORD_PLAIN", record),
        ("V_RECORD_IV", record_iv),
        ("V_RECORD_ENC", record_enc),
        ("The two hash functions of the shim.", None),
        ("V_HASH_MESSAGE", message),
        ("V_HASH_SHA256", wally.sha256(message)),
        ("V_HMAC_KEY", hmac_key),
        ("V_HMAC_SHA256", wally.hmac_sha256(hmac_key, message)),
        ("The fixed random source, in draw order, and its last bytes.", None),
        ("V_RANDOM_SOURCE", source),
        ("V_SEAM_TAIL", seam),
    ]
    return entries


def emit(entries):
    """The text of the header."""
    lines = [LICENSE, "", "#ifndef VECTORS_H", "#define VECTORS_H"]
    for name, value in entries:
        if value is None:
            lines += ["", "/* %s */" % name]
        elif isinstance(value, bool):
            # A parity bit writes as a plain 0 or 1, because a C test
            # compares it with an int. This test precedes the int test.
            lines.append("#define %s\t%d" % (name, value))
        elif isinstance(value, int):
            lines.append("#define %s\t%du" % (name, value))
        else:
            lines.append('#define %s\t"%s"' % (name, value.hex()))
    lines += ["", "#endif /* VECTORS_H */", ""]
    return "\n".join(lines)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "vectors.h"), "w") as out:
        out.write(emit(vectors()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
