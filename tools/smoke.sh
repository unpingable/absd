#!/bin/sh
# Boots the built operator image under QEMU's software emulation (no KVM),
# logs in over SSH, checks that the system answers, that a file written
# before a shutdown is there after the next boot, and that both boots end
# in an orderly halt.
#
#   tools/smoke.sh PRIVATE_KEY [OUT] [PORT]
#
# PRIVATE_KEY is the key whose public half was given to tools/build.sh. OUT
# is the directory build.sh wrote (default out/); PORT defaults to 2222.
# Takes about a minute. This is a smoke test: it shows the tree builds
# something that boots and serves a session, and nothing more. The
# qualification suites are tools/check.sh.
set -eu

top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
key=${1:?usage: smoke.sh PRIVATE_KEY [OUT] [PORT]}
out=${2:-$top/out}
port=${3:-2222}
session() {
    ssh -p "$port" -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR operator@127.0.0.1 "$@"
}
boot() {
    "$top/platform/scripts/boot-operator.sh" "$out" "$port" > "$out/smoke-boot.log" 2>&1 &
    qemu=$!
    tries=0
    until session uname > "$out/smoke-uname.txt" 2>/dev/null; do
        tries=$((tries + 1))
        kill -0 "$qemu" 2>/dev/null || { echo "smoke.sh: QEMU ended before SSH answered" >&2; tail -5 "$out/console.log" >&2; exit 1; }
        test "$tries" -lt 120 || { echo "smoke.sh: no SSH after 10 minutes" >&2; kill "$qemu"; exit 1; }
        sleep 5
    done
}
halt() {
    session shutdown >/dev/null 2>&1 || true
    wait "$qemu" || { echo "smoke.sh: the machine did not halt cleanly" >&2; exit 1; }
    tail -1 "$out/console.log" | grep -q 'ABSD BOOT OK'
}
fail() { echo "smoke.sh: $1" >&2; session shutdown >/dev/null 2>&1 || true; exit 1; }

# One word, no quoting: absd-sh has no quote syntax.
note=smoke-$(date -u +%Y%m%dT%H%M%SZ)
boot
grep -q '^ABSD' "$out/smoke-uname.txt" || fail "uname did not say ABSD"
session 'man intro | head -n 1' | grep -q 'INTRO(1)' || fail "the manual did not answer"
session release | grep -q 'kernel_abi=' || fail "release did not answer"
session "cd /home/operator && echo $note > smoke-note && sync && cat smoke-note" | grep -qx "$note" ||
    fail "a file written was not read back"
halt
boot
session 'cat /home/operator/smoke-note' | grep -qx "$note" || fail "the file did not survive the reboot"
session 'rm /home/operator/smoke-note' || fail "the file could not be removed"
halt
echo "SMOKE OK $(cat "$out/smoke-uname.txt") (two boots, software emulation)"
