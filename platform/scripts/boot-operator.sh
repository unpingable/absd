#!/bin/sh
# Boots the operator image in OUT (scripts/build-operator-image.sh) under
# QEMU and waits for the machine to end (afterboot(8)):
#
#   boot-operator.sh [--local-only --console] OUT [HOST_PORT]
#
# QEMU forwards 127.0.0.1:HOST_PORT (default 2222) to the guest address
# and port the image's /etc/network.conf and /etc/sshd.conf set (read
# from the image by the host's own reader). The console (serial) goes to
# OUT/console.log. `shutdown` from a session halts the machine and this
# script exits 0; `reboot` resets it and the same image boots again.
# Other QEMU exit statuses are reported and returned (7: the boot failed,
# for instance sshd refused a malformed /etc file; see OUT/console.log).
#
# Operator-authorized recovery (docs/WRITABLE-ENTRY.md "Operator-authorized
# resume", OPERATOR-RUNBOOK.md 9a): this script is the launcher the
# authorization protocol relies on. In order: it takes the recovery lock
# OUT/recovery/lock on an open descriptor for the whole run (every other
# supported tool refuses `tool_busy` meanwhile); rotates the previous
# console to OUT/console-<time>.log so OUT/console.log holds only this
# launch; runs the precheck (scripts/storage_fence_resume.py precheck:
# opens the image, takes QEMU's own OFD range lock, evaluates the decision
# table, releases the lock) and refuses with status 7 on its refusal;
# starts QEMU in the background on the same pathname; records `launched`
# (PID, start time, console) only after the process exists; waits. On
# exit, the records are classified again (a consumed record is retired
# with this console as witness, an intact one stays, a launch that never
# printed ABSD KERNEL BOOT is `launch_failed`). Ctrl-C ends the wrapper:
# the script kills its QEMU and classifies the same way. Exit statuses:
# 0 halted; 7 refused before QEMU (precheck, lock) or a boot that failed;
# 6 an authorized launch that never booted (launch_failed, authorization
# intact); 1 the launcher's own bookkeeping failed; otherwise QEMU's.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
usage() { printf '%s\n' "usage: boot-operator.sh [--local-only] [--console] OUT [HOST_PORT]" >&2; }
local_only=0
console_stdio=0
while [ "$#" -gt 0 ]; do
    case $1 in
        --local-only) local_only=1; shift ;;
        --console) console_stdio=1; shift ;;
        --help) usage; exit 0 ;;
        --) shift; break ;;
        -*) usage; exit 2 ;;
        *) break ;;
    esac
done
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || { [ "$local_only" = 1 ] && [ "$console_stdio" != 1 ]; }; then
    usage
    printf '%s\n' "boot-operator: --local-only requires --console for authenticated local recovery" >&2
    exit 2
fi
out=$1
port=${2:-2222}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
test -f "$out/absd-operator.iso"
test -f "$out/absd-operator.img"
# Validate profile and, for SMP, the actual ISO before launch bookkeeping.
python3 "$root/scripts/operator_cpus.py" check "$out/absd-operator.iso" $qemu || exit 7
mkdir -p "$out/recovery"
# The recovery lock, held on descriptor 9 until this script exits.
exec 9>>"$out/recovery/lock"
if ! flock -n 9; then
    printf '%s\n' "boot-operator: tool_busy: $out/recovery/lock is held by another tool or launcher" >&2
    exit 7
fi
# This launch's console: the previous one is kept beside it.
if [ -f "$out/console.log" ]; then
    rotated=$out/console-$(date -u +%Y%m%dT%H%M%SZ)-$$.log
    mv "$out/console.log" "$rotated"
    printf '%s\n' "boot-operator: previous console rotated to $rotated"
fi
console=$out/console.log
precheck_out=$(python3 -I "$root/scripts/storage_fence_resume.py" precheck "$out" --console "$console") || {
    printf '%s\n' "$precheck_out"
    printf '%s\n' "boot-operator: precheck refused the launch (see above)" >&2
    exit 7
}
printf '%s\n' "$precheck_out"
# An authorization the precheck named must resolve to the active id before
# QEMU starts; otherwise its launch could never be recorded.
want=$(printf '%s\n' "$precheck_out" | sed -n 's/^precheck: authorization id=\([0-9a-f]*\) .*/\1/p')
id=
if [ -z "${ABSD_RESUME_TEST_HIDE_ACTIVE:-}" ]; then
    id=$(python3 -I "$root/scripts/storage_fence_resume.py" active-id "$out" 2>/dev/null || true)
fi
if [ -n "$want" ] && [ "$id" != "$want" ]; then
    printf '%s\n' "boot-operator: no active authorization id resolves to $want; not starting QEMU" >&2
    exit 7
fi
if [ "$local_only" = 1 ]; then
    printf '%s\n' "boot-operator: local-only UART console; no network device; console in $console"
else
    set -- $(python3 "$root/scripts/operator_image.py" endpoint "$out/absd-operator.img")
    guest=$1 guest_port=$2
    net=$(printf '%s\n' "$guest" | awk -F. '{print $1 "." $2 "." $3 ".0/24"}')
    printf '%s\n' "boot-operator: ssh -p $port operator@127.0.0.1 reaches $guest:$guest_port; console in $console"
fi
set -- -cpu max,vendor=GenuineIntel,+rdrand -rtc base=utc
if [ "$local_only" = 1 ]; then
    set -- "$@" -nic none
else
    set -- "$@" -netdev user,id=n0,net=$net,hostfwd=tcp:127.0.0.1:$port-$guest:$guest_port -device e1000,netdev=n0
fi
set -- "$@" -display none
if [ "$console_stdio" = 1 ]; then
    set -- "$@" -chardev "stdio,id=operator-console,signal=off,logfile=$console,logappend=off" -serial chardev:operator-console -monitor none
else
    set -- "$@" -serial file:"$console"
fi
set -- "$@" -device isa-debug-exit,iobase=0xf4,iosize=0x04
# Python owns the one child and the inherited recovery lock through reap and
# classification. QEMU never inherits descriptor 9; stdin is inherited only
# for the explicitly requested UART console.
exec python3 -I "$root/scripts/boot_operator_supervisor.py" "$out" "$console" "$id" "$console_stdio" \
    python3 "$root/scripts/served_ram.py" -- python3 "$root/scripts/operator_cpus.py" launch $qemu \
    -cdrom "$out/absd-operator.iso" -drive file="$out/absd-operator.img",format=raw,if=ide,index=0 \
    "$@"
