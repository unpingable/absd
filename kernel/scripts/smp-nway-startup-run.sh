#!/bin/sh
# Closed pre-INIT startup receipt. Drivers remain initialized when this VM exits.
set -eu
kernel=${1:?qualified ELF}; out=${2:?new output directory}; cpus=${3:?4/6}; device=${4:?ata/nvme/net}; control=${5:-}
case "$cpus" in 4|6) ;; *) exit 1 ;; esac
case "$device" in ata) site=1 ;; nvme) site=2 ;; net) site=3 ;; *) exit 1 ;; esac
option=''; marker=''
case "$control" in
 '') ;;
 skip-map) test "$device" = net; option=smp-startup-skip-map; marker='Frozen' ;;
 actor) option=smp-startup-fail-actor; marker='pressure actor terminal status' ;;
 window) option=smp-startup-last-window-omit; marker='startup per-AP window evidence' ;;
 outside-gate) option=smp-startup-last-window-omit; marker='startup window control requires closed N-way gate' ;;
 *) exit 1 ;;
esac
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
command=block-probe
if [ "$device" = net ]; then command=net-probe; fi
options="$command smp-user-pressure smp-user-preempt smp-scheduler-test smp-user-startup smp-startup-nway-test smp-cpus=$cpus nvme-write=absd $option"
if [ "$control" = outside-gate ]; then
 options="block-probe smp-user-pressure smp-user-preempt smp-scheduler-test $option"; cpus=2
fi
printf '%s\n' 'set timeout=0' 'menuentry "ABSD N-way device startup" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
case "$device" in
 ata)
  truncate -s 2M "$out/disk.img"
  set -- -drive "file=$out/disk.img,format=raw,if=ide,index=0"
  ;;
 nvme)
  truncate -s 2M "$out/disk.img"
  set -- -drive "file=$out/disk.img,format=raw,if=none,id=nv0" -device nvme,drive=nv0,serial=absd
  ;;
 net)
  # Private local socket backend, no peer and no host/network forwarding.
  set -- -netdev "socket,id=n0,listen=127.0.0.1:0" -device e1000,netdev=n0
  ;;
esac
qstatus=0
SMP_BENCH_VCPUS=$cpus SMP_TOPOLOGY=separate python3 scripts/smp-user-qemu.py "$out" "$@" > "$out/runner.log" 2>&1 || qstatus=$?
printf '%s\n' "$qstatus" > "$out/runner.status"
if [ -z "$control" ]; then
 test "$qstatus" -eq 3
 python3 scripts/check-smp-nway-startup.py "$out/serial.log" --cpus "$cpus" --site "$site" --placement "$out/vcpu-placement.json" > "$out/oracle.log" 2>&1
 python3 scripts/check-smp-nway-startup.py "$out/serial.log" --cpus "$cpus" --site "$site" --placement "$out/vcpu-placement.json" --self-test > "$out/receipt-controls.log" 2>&1
else
 test "$qstatus" -eq 7
 grep -Fq "$marker" "$out/serial.log"
 python3 - "$out/serial.log" "$control" "$cpus" > "$out/oracle.log" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text(); mode=sys.argv[2]; cpus=int(sys.argv[3])
assert text.count('ABSD PANIC:')==1
assert 'ABSD BOOT OK' not in text and 'SMP NWAY STARTUP OK' not in text
assert 'SMP STARTUP SUMMARY' not in text
panic=text.index('ABSD PANIC:')
if mode=='skip-map':
    assert 'NIC UNAVAILABLE Map { error: Frozen,' in text[:panic]
    assert 'N-way startup selected device unavailable' in text[panic:]
elif mode=='actor':
    witness='SMP STARTUP INJECT role=201 resume-result=refused'
    assert text.count(witness)==1 and text.index(witness)<panic
    assert 'pressure actor terminal status' in text[panic:]
elif mode=='window':
    witness=f'SMP STARTUP INJECT omitted-window-cpu={cpus-1}'
    assert text.count(witness)==1 and text.index(witness)<panic
    assert 'startup per-AP window evidence' in text[panic:]
    assert 'SMP STARTUP INTERVAL END phase=device-probe' in text[:panic]
else:
    assert 'startup window control requires closed N-way gate' in text[panic:]
    assert 'SMP STARTUP PRESSURE CONFIG' not in text
    assert 'NETWORK LINK OK' not in text and 'BLOCK DEVICE OK' not in text
print('N-way startup intended control rejected mode='+mode)
PY
fi
result=0
