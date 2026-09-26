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

# keygen.sh: the tests of the key generator (PROG-KEYGEN).
#
# usage: keygen.sh <program> <object directory>
#
# src/regress/Makefile runs this script. The key file and the owner of
# that file are compile-time constants of PROG-KEYGEN-2, and no build
# flag redirects them. The program writes
# /var/www/fuguoracle/private.key, and it resolves the passwd entry
# of _fuguoracle with getpwnam(3). The test therefore needs root. A
# run without root reports the skip, and it exits zero.
#
# The script creates the group, the user and the directory that the
# package creates (PKG-ORACLE-2, PKG-ORACLE-3), and it removes
# exactly what it created. One trap holds that cleanup, and it runs
# on each exit path. The script removes no user, no group and no
# directory that it found in place. It moves a key file that it found
# in place aside, and it moves that file back.
#
# The script needs no package. perl and openssl of the base system
# derive the public key of the key file, so the answer of the program
# meets an independent one.

set -e

if [ $# -ne 2 ]; then
	echo "usage: keygen.sh <program> <object directory>" >&2
	exit 1
fi
prog=$1
obj=$2
user=_fuguoracle
key_dir=/var/www/fuguoracle
key=$key_dir/private.key
saved=$key_dir/private.key.regress
failures=0

# The scratch of the run. It holds the answer of each run, the copy
# of the first key file, and the files of the derivation.
work=$obj/keygen.work

# The state that the script created. The cleanup removes each one of
# them, and nothing else.
made_group=
made_user=
made_dir=
made_key=
saved_key=

if [ "$(id -u)" -ne 0 ]; then
	echo "keygen.sh: the test of the key generator needs root; skipped" >&2
	exit 0
fi
if [ ! -x "$prog" ]; then
	echo "keygen.sh: $prog: the program is absent; run make in the" \
	    "source directory" >&2
	exit 1
fi

# cleanup():
#	The state of the system before the run. Each step runs, also
#	after a failed step, so the run leaves no residue.
cleanup() {
	set +e
	rm -rf "$work"
	[ -z "$made_key" ] || rm -f "$key"
	[ -z "$saved_key" ] || mv "$saved" "$key"
	[ -z "$made_dir" ] || rmdir "$key_dir"
	[ -z "$made_user" ] || userdel "$user"
	if [ -n "$made_group" ] && getent group "$user" > /dev/null; then
		groupdel "$user"
	fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# fail(message):
#	Report one failed test, and count it.
fail() {
	echo "keygen.sh: $1" >&2
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

# wait_user():
#	The passwd entry of the new user, in the database that
#	getpwnam(3) reads. useradd(8) runs pwd_mkdb(8) in the
#	background, so that entry reaches a program after the call.
wait_user() {
	_try=0
	while [ "$_try" -lt 10 ]; do
		if getent passwd "$user" > /dev/null 2>&1; then
			return
		fi
		sleep 1
		_try=$((_try + 1))
	done
	echo "keygen.sh: $user: the passwd entry of the new user is absent" >&2
	exit 1
}

# pubkey(path):
#	The compressed public key of a private key file, as hex. perl
#	builds the SEC1 structure of the key: the version, the 32
#	bytes of the file, and the object identifier of secp256k1.
#	That structure holds no public field, so LibreSSL computes
#	the point of the scalar. The last 33 bytes of the answer hold
#	that point, in the compressed form.
pubkey() {
	perl -e '
		open(my $fh, "<", $ARGV[0]) or die "$ARGV[0]: $!";
		binmode($fh);
		print pack("H*", "302e0201010420"), do { local $/; <$fh> },
		    pack("H*", "a00706052b8104000a");
	' "$1" > "$work/priv.der"
	if ! openssl ec -inform DER -in "$work/priv.der" -pubout \
	    -outform DER -conv_form compressed > "$work/pub.der" \
	    2> "$work/openssl.err"; then
		cat "$work/openssl.err" >&2
		return 1
	fi
	perl -e '
		open(my $fh, "<", $ARGV[0]) or die "$ARGV[0]: $!";
		binmode($fh);
		print unpack("H*", substr(do { local $/; <$fh> }, -33));
	' "$work/pub.der"
}

rm -rf "$work"
mkdir "$work"

# The group, the user and the directory of PKG-ORACLE-2 and
# PKG-ORACLE-3. The script creates each absent one, and it keeps each
# one that it finds in place.
if ! getent group "$user" > /dev/null 2>&1; then
	groupadd "$user"
	made_group=yes
fi
if ! getent passwd "$user" > /dev/null 2>&1; then
	useradd -g "$user" -d /var/empty -s /sbin/nologin "$user"
	made_user=yes
	wait_user
fi
if [ ! -d "$key_dir" ]; then
	mkdir "$key_dir"
	chown root:"$user" "$key_dir"
	chmod 0710 "$key_dir"
	made_dir=yes
fi
if [ -e "$key" ]; then
	if [ -e "$saved" ]; then
		echo "keygen.sh: $saved: a saved key of an earlier run is" \
		    "in place" >&2
		exit 1
	fi
	mv "$key" "$saved"
	saved_key=yes
fi

# The first run. It draws the static key, it writes the key file, and
# it prints the public key (PROG-KEYGEN-1, PROG-KEYGEN-2).
made_key=yes
rc=0
"$prog" > "$work/first.out" 2> "$work/first.err" || rc=$?
check "the exit status of the first run" 0 "$rc"
[ "$rc" -eq 0 ] || sed 's/^/keygen.sh: the first run: /' "$work/first.err" >&2
if [ ! -f "$key" ]; then
	echo "keygen.sh: $key: the first run wrote no key file" >&2
	exit 1
fi

# The answer holds the compressed public key as 66 hex digits, and
# one line end (PROG-KEYGEN-4).
check "the bytes of the answer of the first run" 67 \
    "$(bytes "$work/first.out")"
grep -q '^[0-9a-f]\{66\}$' "$work/first.out" ||
    fail "the answer of the first run holds no 66 hex digits"
pub=$(cat "$work/first.out")

# The key file holds the 32 bytes of the static key, with the mode
# and the owner of PROG-KEYGEN-2.
check "the bytes of the key file" 32 "$(bytes "$key")"
check "the mode, the owner and the group of the key file" \
    "400 $user $user" "$(stat -f '%Lp %Su %Sg' "$key")"

# The public key of the answer is the public key of the key file
# (PROG-KEYGEN-4).
check "the public key of the first run" "$(pubkey "$key")" "$pub"

# The second run refuses the key file in place. It answers non-zero,
# it prints no public key, and it changes no byte of the file
# (PROG-KEYGEN-3).
cp "$key" "$work/first.key"
rc=0
"$prog" > "$work/second.out" 2> "$work/second.err" || rc=$?
[ "$rc" -ne 0 ] || fail "the second run exits 0"
check "the bytes of the answer of the second run" 0 \
    "$(bytes "$work/second.out")"
cmp -s "$work/first.key" "$key" ||
    fail "the second run changed the key file"

if [ "$failures" -ne 0 ]; then
	echo "keygen.sh: $failures keygen test(s) failed" >&2
	exit 1
fi
