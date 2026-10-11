#!/bin/sh
# Fresh local KVM fixed-work comparison cell; no automatic scaling verdict.
set -eu
kernel=${1:?kernel ELF}
out=${2:?new output directory}
vcpus=${3:?1 or 2}
topology=${4:-separate}
case "$vcpus" in
  1) options='smp-user-bench smp-bench-up' ;;
  2) options='smp-user-bench smp-user-preempt' ;;
  *) exit 1 ;;
esac
if [ "${SMP_SCHEDULER_TEST:-0}" = 1 ]; then
    test "$vcpus" -eq 2
    options="$options smp-scheduler-test"
fi
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
printf '%s\n' 'set timeout=0' 'menuentry "ABSD fixed-work measurement" {' \
  " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$vcpus SMP_TOPOLOGY=$topology python3 scripts/smp-user-qemu.py "$out" || qstatus=$?
test "$qstatus" -eq 3
python3 - "$out" "$vcpus" <<'PY'
import json,re,sys
from pathlib import Path
out=Path(sys.argv[1]);vcpus=int(sys.argv[2]);lines=(out/'serial.log').read_text().splitlines()
assert lines.count('ABSD BOOT OK')==1
assert lines.count('SMP BENCH OK phases=3 tasks=6 work=exact reclaimed=1')==1
assert not any(re.search('PANIC|KERNEL FAULT|FAILED',line) for line in lines)
starts=[line for line in lines if line.startswith('SMP BENCH START ')]
ends=[line for line in lines if line.startswith('SMP BENCH DONE ')]
assert len(starts)==len(ends)==3
rows=[]
for phase,(start,end) in enumerate(zip(starts,ends),1):
    assert start==f'SMP BENCH START phase={phase} vcpus={vcpus}'
    f={key:int(value) for key,value in re.findall(r'([a-z0-9-]+)=(\d+)',end)}
    assert f['phase']==phase and f['vcpus']==vcpus and f['tsc']>0
    assert f['units']==[2*(1<<26),20000,4000][phase-1]
    if vcpus==1: assert f['calls1']==f['dispatch1']==f['preempt1']==0
    else:
        assert f['calls1']>0 and f['dispatch1']>0
        if phase==1: assert f['preempt1']>0
    rows.append(f)
placement=json.loads((out/'vcpu-placement.json').read_text())
assert len(placement['vcpus'])==vcpus and placement['kvm']['enabled']
(out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('SMP BENCH EXACT OK vcpus='+str(vcpus))
PY
result=0
