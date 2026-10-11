#!/bin/sh
# One fresh closed six-job native application capture or typed control.
set -eu
kernel=${1:?qualified native ELF}; out=${2:?new output directory}; cpus=${3:?1/2/4/6}; mode=${4:-positive}
case "$kernel" in /*) ;; *) kernel="$(pwd -P)/$kernel" ;; esac
case "$out" in /*) ;; *) out="$(pwd -P)/$out" ;; esac
cd "$(dirname "$0")/.."
case "$cpus" in 1|2|4|6) ;; *) exit 1 ;; esac
case "$mode" in positive|leaf|leaf-outside|leaf-production|bad-output|no-timer|outside|production) ;; *) exit 1 ;; esac
if [ "$mode" = no-timer ] && [ "$cpus" = 1 ]; then exit 1; fi
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
options='smp-user-bench smp-real-app-scale'
if [ "$cpus" = 1 ]; then
    options="$options smp-bench-up"
else
    options="$options smp-user-preempt smp-scheduler-test smp-cpus=$cpus"
fi
case "$mode" in
    bad-output) options="$options smp-app-scale-bad-output"; expected='native output mismatch';;
    no-timer) options="$options smp-app-scale-no-timer"; expected='native job lacked timer-preemption/resume witness';;
    outside) options='normal smp-real-app-scale'; expected='real application scale requires benchmark test mode';;
    production) expected='SMP USER TEST REQUIRES smp-user-test BUILD';;
    leaf-production) options="$options smp-app-leaf-meter"; expected='SMP USER TEST REQUIRES smp-user-test BUILD';;
    leaf-outside) options='normal smp-app-leaf-meter'; expected='leaf meter requires closed application gate';;
    leaf) options="$options smp-app-leaf-meter"; expected='';;
    positive) expected='';;
esac
printf '%s\n' 'set timeout=0' 'menuentry "ABSD native application scale" {' \
    " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$cpus SMP_TOPOLOGY=separate python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
if [ "$mode" = positive ] || [ "$mode" = leaf ]; then
    test "$qstatus" -eq 3
    set -- --serial "$out/serial.log" --placement "$out/vcpu-placement.json" \
        --metrics "$out/run-metrics.json" --qemu-status "$out/qemu.status" --cpus "$cpus" --results "$out/results.json" --mutants
    if [ "$mode" = leaf ]; then set -- "$@" --leaf; fi
    python3 scripts/check-smp-app-scale.py "$@" > "$out/oracle.log" 2>&1
else
    test "$qstatus" -eq 7
    python3 - "$out/serial.log" "$expected" "$mode" "$cpus" <<'PY'
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(errors='replace').splitlines()
panics=[i for i,line in enumerate(lines) if line.startswith('ABSD PANIC:')]
assert len(panics)==1
assert sys.argv[2] in '\n'.join(lines[panics[0]:panics[0]+6])
assert not any(line.startswith(('SMP APP SCALE OK ','ABSD BOOT OK')) for line in lines)
if sys.argv[3] in ('no-timer','bad-output'):
    starts=[i for i,line in enumerate(lines) if line.startswith('SMP APP SCALE START ')]
    injects=[i for i,line in enumerate(lines) if line.startswith('SMP APP SCALE INJECT ')]
    assert len(starts)==len(injects)==1 and starts[0]<injects[0]<panics[0]
    if sys.argv[3]=='no-timer':
        import re
        publications=[(i,re.fullmatch(r'SMP APP SCALE NATIVE job=5 slot=(\d+) pid=(\d+) parent=(\d+) cpu=(\d+)',line))
                      for i,line in enumerate(lines) if line.startswith('SMP APP SCALE NATIVE job=5 ')]
        assert len(publications)==1 and publications[0][1]
        native=publications[0][1]
        marker=re.fullmatch(r'SMP APP SCALE INJECT job=5 pid=(\d+) cpu=(\d+) saved=1 preempt-credit-omitted=1',lines[injects[0]])
        assert marker and marker[1]==native[2] and marker[2]==native[4]
        assert int(marker[2])==5%int(sys.argv[4])
        traps=[i for i,line in enumerate(lines) if re.fullmatch(
            rf'SMP APP SCALE TRAP job=5 slot={native[1]} pid={native[2]} generation=\d+ cpu={native[4]}',line)]
        exits=[i for i,line in enumerate(lines) if line==f'USER EXIT pid={native[2]} status=0']
        assert len(traps)==len(exits)==1
        assert publications[0][0]<traps[0]<starts[0]<injects[0]<exits[0]<panics[0]
        completions=[(i,line) for i,line in enumerate(lines) if line.startswith('SMP APP SCALE JOB ')]
        assert len(completions)==5
        for job,(i,line) in enumerate(completions):
            row=dict(re.findall(r'([a-z-]+)=(\S+)',line))
            published=[re.fullmatch(rf'SMP APP SCALE NATIVE job={job} slot=(\d+) pid=(\d+) parent=(\d+) cpu=(\d+)',x)
                       for x in lines if x.startswith(f'SMP APP SCALE NATIVE job={job} ')]
            assert len(published)==1 and published[0]
            identity=published[0]
            assert row['job']==str(job) and row['slot']==identity[1] and row['pid']==identity[2]
            assert row['parent']==identity[3] and row['cpu']==identity[4]==str(job%int(sys.argv[4]))
            assert int(row['preempts'])>0 and row['resumed']==row['exited']==row['reclaimed']=='1'
            assert row['input']=='1114112' and row['output']=='107' and exits[0]<i<panics[0]
    else:
        assert lines[injects[0]]=='SMP APP SCALE INJECT kind=output job=5 observed-byte-substituted=1'
else:
    assert not any(line.startswith('SMP APP SCALE ') for line in lines)
    assert not any(line.startswith('SMP APP LEAF') for line in lines)
PY
fi
result=0
