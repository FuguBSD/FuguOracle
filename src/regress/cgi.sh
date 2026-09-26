#!/bin/sh
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

# cgi.sh: the tests of the two programs (PROG-CGI, PROG-KEYGEN).
#
# usage: cgi.sh <program> <object directory>
#
# src/regress/Makefile runs this script. The program runs directly, with
# the CGI variables in the environment and the body on standard
# input. The script reads the status, the header block and the body
# of each answer. The object directory holds the two compile-time
# paths of the build: the record directory and the key file.
#
# The regress build draws each random byte from the file that
# FUGUORACLE_RANDOM names (SEC-RANDOM-2). The program unveils the
# key file and the record directory alone, so that file sits in the
# record directory.
#
# Each case reads the log lines of its request from /var/log/daemon.
# The program logs at LOG_DAEMON, and the syslog.conf of the base
# system sends daemon.info and each higher level to that file
# (SEC-LOGGING-1). The outcome class of the LOG_INFO line is the one
# answer that separates a junk path from a real one, because
# OPS-JUNK-2 makes the status, the headers and the envelope size
# identical. The wipe line of LOG_WARNING and the failure line of
# LOG_ERR land in the same file (OPS-WIPE-3, SEC-LOGGING-2).
#
# The script needs no package. perl and openssl of the base system
# convert the hex of tests/vectors/vectors.h, and they build one
# record. That header sits two directories up, beside the host
# harness (ARCH-BUILD-5).

set -e

if [ $# -ne 2 ]; then
	echo "usage: cgi.sh <program> <object directory>" >&2
	exit 1
fi
prog=$1
obj=$2
dir=$(dirname "$0")
src=$dir/..
vectors=$dir/../../tests/vectors/vectors.h
pins=$obj/pins
key=$obj/private.key
rand=$pins/.random
log=/var/log/daemon
failures=0

# The scratch of the run. Each case writes the answer, the body and
# the log of one request there.
work=$obj/cgi.work
rm -rf "$work"
mkdir "$work"
trap 'rm -rf "$work"' EXIT

# The bound of the line count of ARCH-LAYOUT-4. The target is about
# 1,500 lines, and this bound answers real growth alone.
LINE_BOUND=1800

# fail(message):
#	Report one failed test, and count it.
fail() {
	echo "cgi.sh: $1" >&2
	failures=$((failures + 1))
}

# check(name, want, got):
#	One test of an exact value.
check() {
	[ "$2" = "$3" ] || fail "$1: want \"$2\", got \"$3\""
}

# bytes(path):
#	The bytes of one file, without the pad of wc(1).
bytes() {
	wc -c < "$1" | tr -d ' '
}

# vector(name):
#	The hex string of one #define of vectors.h.
vector() {
	sed -n "s/^#define[[:space:]]*$1[[:space:]]*\"\([0-9a-f]*\)\".*/\1/p" \
	    "$vectors"
}

# unhex(hex):
#	The bytes of a hex string, on standard output.
unhex() {
	perl -e 'print pack("H*", $ARGV[0])' "$1"
}

# b64(hex):
#	The base64 of a hex string, on one line.
b64() {
	perl -MMIME::Base64 -e \
	    'print encode_base64(pack("H*", $ARGV[0]), "")' "$1"
}

# send(method, path, body file, content length):
#	One request of the program. The answer lands in two files:
#	the bytes of the wire, and the same text without the CR of
#	each line end.
send() {
	log_off=$(bytes "$log")
	REQUEST_METHOD="$1" DOCUMENT_URI="$2" CONTENT_LENGTH="$4" \
	    FUGUORACLE_RANDOM="$rand" "$prog" < "$3" > "$work/answer"
	tr -d '\r' < "$work/answer" > "$work/text"
}

# post(path, envelope):
#	One POST request that carries a request envelope, as the
#	base64 of the data member (PROTO-HTTP-7).
post() {
	printf '{"data": "%s"}' "$(b64 "$2")" > "$work/body"
	send POST "$1" "$work/body" "$(bytes "$work/body")"
}

# status():
#	The status of the answer.
status() {
	sed -n '1s/^Status: \([0-9]*\).*/\1/p' "$work/text"
}

# head_of(path):
#	The header block of the answer, in a file of its own.
head_of() {
	sed -n '1,/^$/p' "$work/text" > "$1"
}

# envelope_bytes():
#	The bytes of the response envelope of the answer. One newline
#	follows the closing brace, and no other byte. A body of
#	another shape answers -1 (PROTO-RESPONSE-3).
envelope_bytes() {
	sed -e '1,/^$/d' "$work/text" | perl -MMIME::Base64 -e '
		my $body = do { local $/; <STDIN> };
		$body = "" if !defined $body;
		print $body =~ m/\A\{"data":"([A-Za-z0-9+\/=]+)"\}\n\z/ ?
		    length(decode_base64($1)) : -1;
	'
}

# log_holds(name, text):
#	One test of the log of the last request. The log takes one
#	line that ends with text. syslogd(8) writes each line after
#	the exit of the program, so this call waits for it. The
#	bytes of the log stay in $work/log.
log_holds() {
	_try=0
	while [ "$_try" -lt 5 ]; do
		tail -c "+$((log_off + 1))" "$log" > "$work/log"
		if grep -q "fuguoracle\[[0-9]*\]: $2\$" "$work/log"; then
			return
		fi
		sleep 1
		_try=$((_try + 1))
	done
	fail "$1: the log holds no line \"$2\""
}

# class_is(name, class, status):
#	The log line of the last request holds one outcome class and
#	the status of the answer (SEC-LOGGING-2).
class_is() {
	log_holds "$1" "$2 $3"
}

# reset():
#	An empty record store, and a fresh random source. Each
#	program of the regress build opens that source once
#	(SEC-RANDOM-2).
reset() {
	rm -rf "$pins"
	mkdir "$pins"
	dd if=/dev/urandom of="$rand" bs=1024 count=4 2>/dev/null
}

# tweak_envelope(payload length):
#	One request envelope of the tweak vector, with a payload of
#	zero bytes. The counter and the cke of that vector name the
#	two request keys, so the script seals the envelope without a
#	call of the shim (PROTO-ENVELOPE, PROTO-ENCRYPT-3).
tweak_envelope() {
	_iv=000102030405060708090a0b0c0d0e0f
	_le=$(perl -e 'print unpack("H*", pack("V", $ARGV[0]))' \
	    "$tweak_counter")
	perl -e 'print "\0" x $ARGV[0]' "$1" > "$work/payload"
	openssl enc -aes-256-cbc -K "$tweak_enc_key" -iv "$_iv" \
	    -in "$work/payload" -out "$work/ct"
	perl -MDigest::SHA=hmac_sha256 -e '
		my ($cke, $le, $ivhex, $mac, $file) = @ARGV;
		open(my $fh, "<", $file) or die "$file: $!";
		binmode($fh);
		my $enc = pack("H*", $ivhex) . do { local $/; <$fh> };
		print $cke, $le, unpack("H*",
		    $enc . hmac_sha256($enc, pack("H*", $mac)));
	' "$tweak_cke" "$_le" "$_iv" "$tweak_mac_key" "$work/ct"
}

# wrong_pin_record(path, count):
#	The record of the client of the transcript, with the hash of
#	another PIN and the count of the bad attempts. No request can
#	carry a wrong PIN for an existing record, because the
#	signature of the payload covers the pin_secret
#	(PROTO-PAYLOAD-3). The script writes the record instead, from
#	the two record keys of the client (STORE-KEYS-1,
#	STORE-RECORD).
wrong_pin_record() {
	_iv=0f0e0d0c0b0a09080706050403020100
	_keys=$(perl -MDigest::SHA=sha256,hmac_sha256 -e '
		my ($priv, $pub) = map { pack("H*", $_) } @ARGV;
		my $data = hmac_sha256("pin_data", $priv);
		print unpack("H*", hmac_sha256($pub, $data)), " ",
		    unpack("H*", hmac_sha256(sha256($pub), $data));
	' "$static_priv" "$client_pub")

	# The plaintext of PINDB_PLAIN_LEN bytes: a hash that no PIN
	# answers, a zero key share, the count, and no counter.
	perl -e 'print "\0" x 64, chr($ARGV[0]), "\0" x 4' "$2" \
	    > "$work/plain"
	openssl enc -aes-256-cbc -K "${_keys% *}" -iv "$_iv" \
	    -in "$work/plain" -out "$work/ct"
	perl -MDigest::SHA=hmac_sha256 -e '
		my ($auth, $ivhex, $file) = @ARGV;
		open(my $fh, "<", $file) or die "$file: $!";
		binmode($fh);
		my $enc = pack("H*", $ivhex) . do { local $/; <$fh> };
		my $msg = chr(1) . $enc;

		# The layout of one record: the version, the
		# authenticator of the version and the enc field, then
		# that field (STORE-RECORD).
		print chr(1), hmac_sha256($msg, pack("H*", $auth)), $enc;
	' "${_keys#* }" "$_iv" "$work/ct" > "$1.new"
	mv "$1.new" "$1"
}

# The vectors of the run: the static key, the client of the
# transcript, the transcript pair, and the tweak.
static_priv=$(vector V_STATIC_PRIV)
client_pub=$(vector V_CLIENT_PUB)
set_env=$(vector V_SET_ENVELOPE)
get_env=$(vector V_GET_ENVELOPE)
tweak_cke=$(vector V_TWEAK_CKE)
tweak_enc_key=$(vector V_TWEAK_REQUEST_ENC_KEY)
tweak_mac_key=$(vector V_TWEAK_REQUEST_MAC_KEY)
tweak_counter=$(sed -n \
    's/^#define[[:space:]]*V_TWEAK_COUNTER[[:space:]]*\([0-9]*\)u.*/\1/p' \
    "$vectors")
if [ -z "$static_priv" ] || [ -z "$get_env" ] || [ -z "$tweak_counter" ]; then
	echo "cgi.sh: vectors.h holds no vector" >&2
	exit 1
fi
if [ ! -r "$log" ]; then
	echo "cgi.sh: $log: the log of the program is absent" >&2
	exit 1
fi

# The static key of the vectors, in the key file of the build. The
# program reads 32 raw bytes from that path (PROG-CGI-4).
unhex "$static_priv" > "$key"

# The liveness answer of GET / (PROTO-HTTP-1, PROTO-HTTP-6). The
# answer holds the status line and the empty line of PROG-CGI-3, and
# no other byte.
reset
send GET / /dev/null 0
check "the liveness status" 200 "$(status)"
printf 'Status: 200\r\n\r\n' > "$work/want"
cmp -s "$work/want" "$work/answer" ||
    fail "the liveness answer holds another byte"
class_is "the liveness answer" ok_live 200

# An unknown path and a wrong method (PROTO-HTTP-5).
send GET /nope /dev/null 0
check "an unknown path" 404 "$(status)"
send POST / /dev/null 0
check "a wrong method on /" 405 "$(status)"
send GET /set_pin /dev/null 0
check "a wrong method on /set_pin" 405 "$(status)"
class_is "a wrong method" reject 405

# A body above the cap of PROTO-HTTP-2. The program answers the
# value of CONTENT_LENGTH, and it reads no byte of the body.
send POST /set_pin /dev/null 4097
check "a body above the cap" 413 "$(status)"
class_is "a body above the cap" reject 413

# The four malformed bodies (PROTO-HTTP-7, PROTO-ENVELOPE-1).
printf '{"data": ' > "$work/body"
send POST /set_pin "$work/body" "$(bytes "$work/body")"
check "malformed JSON" 400 "$(status)"

printf '{"data": "!!!!"}' > "$work/body"
send POST /set_pin "$work/body" "$(bytes "$work/body")"
check "bad base64" 400 "$(status)"

value=$(b64 "$set_env")
printf '{"data": "%s", "data": "%s"}' "$value" "$value" > "$work/body"
send POST /set_pin "$work/body" "$(bytes "$work/body")"
check "a duplicate data member" 400 "$(status)"

post /set_pin 00112233445566778899aabbccddeeff
check "a short envelope" 400 "$(status)"
class_is "a short envelope" reject 400

# An unknown member and insignificant whitespace (PROTO-HTTP-7). The
# scanner steps over the value of each unknown member, and it reads
# the extent of a nested object, a nested array and a nested string.
# Each body below carries the get_pin envelope of the transcript, and
# the store holds no record. The scanner reads each of the two bodies,
# so each one answers the junk path with 200 and an envelope of 96
# bytes.
reset
value=$(b64 "$get_env")
printf '{"a": {"b": [1, "}"], "c": null}, "data": "%s", "d": [{}]}' \
    "$value" > "$work/body"
send POST /get_pin "$work/body" "$(bytes "$work/body")"
check "an unknown member" 200 "$(status)"
check "an unknown member answers an envelope" 96 "$(envelope_bytes)"

printf ' {\n\t"data"\r\n\t: "%s"\n} ' "$value" > "$work/body"
send POST /get_pin "$work/body" "$(bytes "$work/body")"
check "insignificant whitespace" 200 "$(status)"
check "whitespace answers an envelope" 96 "$(envelope_bytes)"

# A payload of another length is an internal failure, and no client
# error (PROTO-PAYLOAD-5, OPS-SET-7).
reset
post /set_pin "$(tweak_envelope 64)"
check "a payload of another length" 500 "$(status)"
class_is "a payload of another length" error 500

# The round trip of the transcript (OVW-PURPOSE-3, PROTO-HTTP-6).
# The replay counter of the get_pin envelope is above the counter of
# the set_pin envelope.
reset
post /set_pin "$set_env"
check "the set_pin status" 200 "$(status)"
check "the set_pin header" "Content-Type: application/json" \
    "$(sed -n '2p' "$work/text")"
check "the set_pin envelope" 96 "$(envelope_bytes)"
class_is "the set_pin" ok_set 200

# The log line of a request holds no hex of that request
# (SEC-LOGGING-3).
if grep -qi "$(echo "$set_env" | cut -c 1-32)" "$work/log"; then
	fail "the log line holds the hex of the request"
fi

post /get_pin "$get_env"
check "the get_pin status" 200 "$(status)"
check "the get_pin header" "Content-Type: application/json" \
    "$(sed -n '2p' "$work/text")"
check "the get_pin envelope" 96 "$(envelope_bytes)"
class_is "the get_pin" ok_get 200
head_of "$work/real"

# A replayed get_pin takes the junk path, and it moves no count
# (OPS-JUNK-1). The stored counter of the record is the counter of
# the answer above.
post /get_pin "$get_env"
check "a replayed get_pin" 200 "$(status)"
check "a replayed get_pin answers an envelope" 96 "$(envelope_bytes)"
class_is "a replayed get_pin" junk 200
head_of "$work/junk1"

# A replayed set_pin is an internal failure (OPS-SET-2, OPS-SET-7).
post /set_pin "$set_env"
check "a replayed set_pin" 500 "$(status)"
class_is "a replayed set_pin" error 500

# A missing record takes the junk path (OPS-GET-2, OPS-JUNK-1).
reset
post /get_pin "$get_env"
check "a missing record" 200 "$(status)"
check "a missing record answers an envelope" 96 "$(envelope_bytes)"
class_is "a missing record" junk 200
head_of "$work/junk2"

# A wrong PIN takes the junk path as well, and the record then holds
# one more count (OPS-GET-5, OPS-JUNK-1).
reset
post /set_pin "$set_env"
record=$(ls "$pins"/*.pin)
wrong_pin_record "$record" 0
cp "$record" "$work/before"
post /get_pin "$get_env"
check "a wrong PIN" 200 "$(status)"
check "a wrong PIN answers an envelope" 96 "$(envelope_bytes)"
class_is "a wrong PIN" junk 200
head_of "$work/junk3"
if cmp -s "$work/before" "$record"; then
	fail "a wrong PIN: the record holds no count of the attempt"
fi

# The three junk paths answer one status and one header set, and the
# real answer above holds the same ones (OPS-JUNK-2).
cmp -s "$work/junk1" "$work/junk2" ||
    fail "a replay and a missing record answer two header sets"
cmp -s "$work/junk1" "$work/junk3" ||
    fail "a replay and a wrong PIN answer two header sets"
cmp -s "$work/junk1" "$work/real" ||
    fail "a junk path and the real answer hold two header sets"

# The third strike destroys the key share, and it writes one line at
# LOG_WARNING (OPS-GET-6, OPS-WIPE-3). The record below carries two
# bad attempts, so the wrong PIN of the request is the third one.
reset
post /set_pin "$set_env"
record=$(ls "$pins"/*.pin)
wrong_pin_record "$record" 2
post /get_pin "$get_env"
check "a third strike" 200 "$(status)"
class_is "a third strike" junk 200
log_holds "a third strike" "a third strike destroyed a key share"

# An I/O failure of the load is an internal failure (OPS-GET-7), and
# it writes one line at LOG_ERR (SEC-LOGGING-2). A directory at the
# record path answers each open call, and no read call of it.
reset
post /set_pin "$set_env"
record=$(ls "$pins"/*.pin)
rm -f "$record"
mkdir "$record"
post /get_pin "$get_env"
check "an I/O failure on load" 500 "$(status)"
class_is "an I/O failure on load" error 500
log_holds "an I/O failure on load" "the read of a record failed"
rmdir "$record"

# Each program links static (ARCH-DEPS-4, ARCH-STACK-3). ldd(1)
# prints one dlib line for a static program, and an exe line with
# one rlib line for each shared library of a dynamic one. file(1)
# reports one type for both, so it answers nothing here. Each
# program builds in a directory of its own under $src, in obj when
# make obj made one (ARCH-BUILD-2).
for program in fuguoracle fuguoracle-keygen; do
	path=$src/$program/$program
	if [ -d "$src/$program/obj" ]; then
		path=$src/$program/obj/$program
	fi
	if [ ! -x "$path" ]; then
		fail "$program: the program is absent; run make in $src"
		continue
	fi
	ldd "$path" > "$work/ldd" 2>&1 || true
	dlib=$(grep -c '[[:space:]]dlib[[:space:]]' "$work/ldd" || true)
	rlib=$(grep -c '[[:space:]]rlib[[:space:]]' "$work/ldd" || true)
	check "$program links static" "1 0" "$dlib $rlib"
done

# The line count of the C sources stays under the bound of
# ARCH-LAYOUT-4. The count reads the lines outside the comments and
# the blank lines. $src holds the flat sources alone, so the test
# sources of this directory stay out of the count.
lines=$(awk '
{
	line = $0
	out = ""
	while (length(line) > 0) {
		if (comment) {
			p = index(line, "*/")
			if (p == 0)
				line = ""
			else {
				comment = 0
				line = substr(line, p + 2)
			}
		} else {
			p = index(line, "/*")
			if (p == 0) {
				out = out line
				line = ""
			} else {
				out = out substr(line, 1, p - 1)
				line = substr(line, p + 2)
				comment = 1
			}
		}
	}
	gsub(/[ \t]/, "", out)
	if (out != "")
		code++
}
END { print code + 0 }
' "$src"/*.c)
if [ "$lines" -eq 0 ]; then
	fail "the count of the lines of the C sources failed"
elif [ "$lines" -gt "$LINE_BOUND" ]; then
	fail "the C sources hold $lines lines, above the bound $LINE_BOUND"
fi

rm -f "$key"
rm -rf "$pins"
if [ "$failures" -ne 0 ]; then
	echo "cgi.sh: $failures cgi test(s) failed" >&2
	exit 1
fi
