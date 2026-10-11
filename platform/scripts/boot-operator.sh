#!/bin/sh
# Boots the operator image in OUT (scripts/build-operator-image.sh) under
# QEMU and waits for the machine to end (afterboot(8)):
#
#   boot-operator.sh OUT [HOST_PORT]
#
# QEMU forwards 127.0.0.1:HOST_PORT (default 2222) to the guest address
# and port the image's /etc/network.conf and /etc/sshd.conf set (read
# from the image by the host's own reader). The console (serial) goes to
# OUT/console.log. `shutdown` from a session halts the machine and this
# script exits 0; `reboot` resets it and the same image boots again.
# Other QEMU exit statuses are reported and returned (7: the boot failed,
# for instance sshd refused a malformed /etc file; see OUT/console.log).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?usage: boot-operator.sh OUT [HOST_PORT]}
port=${2:-2222}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
test -f "$out/absd-operator.iso"
test -f "$out/absd-operator.img"
set -- $(python3 "$root/scripts/operator_image.py" endpoint "$out/absd-operator.img")
guest=$1 guest_port=$2
net=$(printf '%s\n' "$guest" | awk -F. '{print $1 "." $2 "." $3 ".0/24"}')
printf '%s\n' "boot-operator: ssh -p $port operator@127.0.0.1 reaches $guest:$guest_port; console in $out/console.log"
status=0
$qemu -cpu max,vendor=GenuineIntel,+rdrand -rtc base=utc \
    -cdrom "$out/absd-operator.iso" -drive file="$out/absd-operator.img",format=raw,if=ide,index=0 \
    -netdev user,id=n0,net=$net,hostfwd=tcp:127.0.0.1:$port-$guest:$guest_port -device e1000,netdev=n0 \
    -display none -serial file:"$out/console.log" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$?
case $status in
3) printf '%s\n' "boot-operator: the machine halted"; exit 0 ;;
*) printf '%s\n' "boot-operator: QEMU exited with status $status (see $out/console.log)" >&2; exit "$status" ;;
esac
