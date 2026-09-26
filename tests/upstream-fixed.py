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

"""upstream-fixed.py: the upstream server on the fixed random source.

usage: upstream-fixed.py <random file> <port>

tests/interop puts this program into the OpenBSD guest, and it runs
the program there, in a directory that holds the private key file of
the upstream server and a 'pins' directory. The program puts a reader
of the fixed random file in place of os.urandom, then it imports the
upstream Flask app and runs it on the port (D-12, TEST-ACCEPT-1).

Every draw of the upstream server goes through os.urandom: the two
IVs of lib.py, and the junk key and the server entropy of pindb.py.
The libwally calls of the server draw nothing. The tweak, the
recovery and each AES call take every input as an argument, and the
server signs nothing in protocol v2. lib.py and pindb.py read the
function from the os module at each call, so the reader covers each
draw of the draw table of TEST-ACCEPT-2.

Each request of the FuguOracle service is one process, and the seam
of that process opens the file at its first draw (SEC-RANDOM-2), so
each request of the service reads the file from its first byte. This
program rewinds the file before each request, so the two servers draw
the same bytes for the same request. A short read raises, and the app
then answers 500: a draw beyond the file is a fault of the table. The
server runs one thread, so the draws of one request stay in order.
"""

import os
import sys

if len(sys.argv) != 3:
    sys.exit('usage: upstream-fixed.py <random file> <port>')
SOURCE = open(sys.argv[1], 'rb')
PORT = int(sys.argv[2])


def fixed_urandom(n):
    """The next n bytes of the fixed random source."""
    data = SOURCE.read(n)
    if len(data) != n:
        raise RuntimeError('the fixed random source holds too few bytes')
    return data


os.urandom = fixed_urandom

from blind_pin_server.flaskserver import app  # noqa: E402


@app.before_request
def rewind():
    SOURCE.seek(0)


app.run(host='127.0.0.1', port=PORT, threaded=False)
