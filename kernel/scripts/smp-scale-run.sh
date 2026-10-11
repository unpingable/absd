#!/bin/sh
# One fresh bounded fixed-work scaling qualification/control capture.
set -eu
kernel=${1:?qualified ELF}; out=${2:?new output directory}; cpus=${3:?1/2/4/6}; mode=${4:-positive}
case "$kernel" in /*) ;; *) kernel="$(pwd -P)/$kernel" ;; esac
case "$out" in /*) ;; *) out="$(pwd -P)/$out" ;; esac
cd "$(dirname "$0")/.."
case "$cpus" in 1|2|4|6) ;; *) exit 1 ;; esac
case "$mode" in positive|meter-off|omit|wrong|short|outside) ;; *) exit 1 ;; esac
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
options='smp-user-bench smp-scale-test'
if [ "$cpus" = 1 ]; then
    options="$options smp-bench-up"
else
    options="$options smp-user-preempt smp-scheduler-test smp-cpus=$cpus"
fi
case "$mode" in
    meter-off) options="$options smp-scale-meter-off"; expected='';;
    omit) options="$options smp-scale-omit-path"; expected='meter path sum mismatch';;
    wrong) options="$options smp-scale-wrong-path"; expected='meter path work count mismatch';;
    short) options="$options smp-scale-short-work"; expected='scale work shortfall';;
    outside) options='normal smp-scale-test'; expected='scale requires benchmark qualification';;
    positive) expected='';;
esac
printf '%s\n' 'set timeout=0' 'menuentry "ABSD SMP scale qualification" {' \
    " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$cpus SMP_TOPOLOGY=separate python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
if [ "$mode" = positive ]; then
    test "$qstatus" -eq 3
    python3 scripts/check-smp-scale.py "$out/serial.log" "$out/vcpu-placement.json" \
        --metrics "$out/run-metrics.json" --cpus "$cpus" --meter 1 \
        --results "$out/results.json" --mutants > "$out/oracle.log" 2>&1
elif [ "$mode" = meter-off ]; then
    test "$qstatus" -eq 3
    python3 scripts/check-smp-scale.py "$out/serial.log" "$out/vcpu-placement.json" \
        --metrics "$out/run-metrics.json" --cpus "$cpus" --meter 0 \
        --results "$out/results.json" > "$out/oracle.log" 2>&1
else
    test "$qstatus" -eq 7
    python3 - "$out/serial.log" "$expected" "$mode" "$cpus" "$out" <<'PY'
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(errors='replace').splitlines()
markers=[i for i,line in enumerate(lines) if line.startswith('ABSD PANIC:')]
if len(markers)!=1:
    raise SystemExit('expected exactly one panic record')
block='\n'.join(lines[markers[0]:markers[0]+6])
if block.count(sys.argv[2])!=1:
    raise SystemExit('expected one typed panic message in panic record')
if sys.argv[3] == 'wrong':
    import re,json
    cpus=int(sys.argv[4])
    exact=f'SMP SCALE INJECT kind=wrong-path phase=2 cpu={cpus-1} from=getpid to=other once=1'
    def check_wrong(rows):
        inject=[i for i,x in enumerate(rows) if x.startswith('SMP SCALE INJECT ')]
        work=[(i,re.fullmatch(r'SMP SCALE WORK phase=2 index=([0-5]) units=10000 checksum=0',x)) for i,x in enumerate(rows)]
        work=[(i,int(m[1])) for i,m in work if m]
        starts=[i for i,x in enumerate(rows) if x.startswith('SMP SCALE START phase=2 ')]
        panics=[i for i,x in enumerate(rows) if x.startswith('ABSD PANIC:')]
        assert len(inject)==len(starts)==len(panics)==1 and rows[inject[0]]==exact
        assert len(work)==6 and {index for _,index in work}==set(range(6))
        assert starts[0] < inject[0] < min(i for i,_ in work) <= max(i for i,_ in work) < panics[0]
    check_wrong(lines)
    changed=list(lines); injection=next(i for i,x in enumerate(changed) if x==exact)
    record=changed.pop(injection); changed.insert(next(i for i,x in enumerate(changed) if x.startswith('ABSD PANIC:'))+1,record)
    assert changed!=lines
    try: check_wrong(changed)
    except AssertionError: pass
    else: raise SystemExit('moved injection control accepted')
    Path(sys.argv[5],'wrong-receipt-controls.json').write_text(json.dumps({'moved-injection':'rejected'})+'\n')
PY
    if grep -Eq '^(ABSD BOOT OK|SMP SCALE OK )' "$out/serial.log"; then exit 1; fi
fi
result=0
