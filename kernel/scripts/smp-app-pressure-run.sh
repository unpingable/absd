#!/bin/sh
# Reuse one qualified native-input image for fresh topology/placement boots.
set -eu
kernel=${1:?qualified native ELF}; out=${2:?new directory}
cpus=${3:?2/4/6}; target=${4:?AP CPU}; expected=${5:?exact output fixture}; mutant=${6:-}
case "$cpus" in 2|4|6) ;; *) exit 1;; esac
case "$target" in 1|2|3|4|5) ;; *) exit 1;; esac
test "$target" -lt "$cpus"
option=''
case "$mutant" in '' ) ;; skip-timer) option=smp-app-skip-timer;; *) exit 1;; esac
cd "$(dirname "$0")/.."
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
cp "$expected" "$out/expected.txt"
sha256sum "$kernel" "$out/expected.txt" > "$out/inputs.sha256"
options="external smp-user-pressure smp-user-preempt smp-scheduler-test smp-multicore-pressure smp-ap-app smp-app-cpu=$target $option"
if [ "$cpus" != 2 ]; then options="$options smp-cpus=$cpus"; fi
printf '%s\n' 'set timeout=0' 'menuentry "ABSD real AP application pressure" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$cpus SMP_TOPOLOGY=separate python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
python3 - "$out/vcpu-placement.json" "$cpus" <<'PY'
import json, sys
from pathlib import Path
p=json.loads(Path(sys.argv[1]).read_text()); n=int(sys.argv[2])
assert p['kvm']=={'enabled':True,'present':True}
assert p['host_topology']=='separate'
assert p['guest_topology']=={'sockets':1,'cores':n,'threads':1}
v=p['vcpus']
assert len(v)==n and sorted(x['cpu-index'] for x in v)==list(range(n))
assert len({(x['host-package'],x['host-core']) for x in v})==n
assert all(x['affinity']==[x['host-cpu']] for x in v)
PY
if [ -z "$mutant" ]; then
    test "$qstatus" -eq 3
    python3 scripts/check-external-output.py "$out/serial.log" "$out/expected.txt" > "$out/output-oracle.log" 2>&1
    python3 scripts/check-smp-app-pressure.py "$out/serial.log" --cpus "$cpus" --app-cpu "$target" > "$out/oracle.log" 2>&1
else
    test "$qstatus" -eq 7
    grep -Fq 'native application lacked task-specific preemption' "$out/serial.log"
    if grep -qx 'ABSD BOOT OK' "$out/serial.log"; then exit 1; fi
    python3 - "$out/serial.log" "$target" <<'PY'
import re, sys
from pathlib import Path
rows=Path(sys.argv[1]).read_text().splitlines()
traps=[r for r in rows if r.startswith('SMP APP TRAP ')]
inject=[r for r in rows if r.startswith('SMP APP PRESSURE INJECT ')]
assert len(traps)==len(inject)==1
def f(r): return dict(re.findall(r'([a-z0-9-]+)=(\S+)',r))
t,i=f(traps[0]),f(inject[0])
assert t['cpu']==i['cpu']==sys.argv[2] and t['pid']==i['pid']
assert i['timer-witness-omitted']=='1'
failure=next(j for j,r in enumerate(rows) if 'native application lacked task-specific preemption' in r)
assert rows.index(traps[0])<failure and rows.index(inject[0])<failure
assert t['cpl']=='3' and t['cr3']=='owned'
assert not any(r.startswith('SMP APP SUMMARY ') for r in rows)
print('SMP APP native timer witness negative control rejected at intended assertion')
PY
fi
result=0
