#!/bin/sh
# Run one bounded CPU1 userspace regression against an existing kernel ELF.
set -eu

kernel=${1:?usage: smp-user-regression.sh KERNEL OUT MODE}
out=${2:?usage: smp-user-regression.sh KERNEL OUT MODE}
mode=${3:?usage: smp-user-regression.sh KERNEL OUT MODE}
preempt=${4:-cooperative}
extra_options=${5:-}
case "$preempt" in cooperative|preemptive|startup) ;; *) exit 1 ;; esac
caller_dir=$PWD
case "$kernel" in /*) ;; *) kernel=$caller_dir/$kernel ;; esac
case "$out" in /*) ;; *) out=$caller_dir/$out ;; esac
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
test -f "$kernel"
mkdir "$out"
result=1
finish() {
    printf '%s\n' "$result" > "$out/status.tmp"
    mv "$out/status.tmp" "$out/status"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

die() {
    printf 'smp-user-regression: %s\n' "$*" >&2
    exit 1
}

case "$mode" in
    rt-test|rt-class|block-ata|block-nvme|net|default|guards) ;;
    *) die "unknown mode: $mode" ;;
esac

test -c /dev/kvm || die '/dev/kvm is unavailable'
test -r /dev/kvm && test -w /dev/kvm || die '/dev/kvm is not accessible'
sha256sum "$kernel" > "$out/kernel.sha256"
qemu-system-x86_64 --version > "$out/qemu.version"
uname -a > "$out/host.version"
printf 'mode=%s\naccel=kvm vcpus=2 memory=256MiB\n' "$mode" > "$out/identity"

make_iso() {
    case_dir=$1
    options=$2
    title=$3
    mkdir -p "$case_dir/iso/boot/grub"
    cp "$kernel" "$case_dir/iso/boot/absd-kernel"
    printf '%s\n' 'set timeout=0' "menuentry \"$title\" {" \
        "  multiboot2 /boot/absd-kernel $options" '  boot' '}' \
        > "$case_dir/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$case_dir/boot.iso" "$case_dir/iso" \
        > "$case_dir/iso.log" 2>&1
}

run_pinned() {
    case_dir=$1
    expected=$2
    shift 2
    status=0
    timeout 140s python3 scripts/smp-user-qemu.py "$case_dir" "$@" \
        > "$case_dir/runner.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$case_dir/runner.status"
    test "$status" -eq "$expected" || die "$case_dir: QEMU status $status, expected $expected"
}

check_no_failure_records() {
    case_log=$1
    if grep -Eq 'ABSD PANIC:|KERNEL FAULT|FAILED' "$case_log"; then
        die "$case_log contains a failure record"
    fi
}

check_pressure_records() {
    case_dir=$1
    device=$2
    case_log=$case_dir/serial.log
    if [ "$preempt" != cooperative ]; then
        python3 - "$case_log" > "$case_dir/timer-oracle.log" <<'PY'
import re, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
records = [line for line in lines if line.startswith('SMP TIMER SUMMARY cpu=1 ')]
assert len(records) == 1
values = {key: int(value) for key, value in re.findall(r'([a-z0-9-]+)=(\d+)', records[0])}
assert values['user-irqs'] > 0 and values['switches1'] > 0, records
print(records[0])
PY
    fi
    if [ "$preempt" = startup ]; then
        python3 - "$case_log" "$device" > "$case_dir/startup-oracle.log" <<'PY'
import re, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
assert lines.count('SMP STARTUP AP READY cpu=1') == 1
assert lines.count('SMP MMIO FROZEN new-map=refused') == 1
records = [line for line in lines if line.startswith('SMP STARTUP SUMMARY ')]
assert len(records) == 1 and records[0].endswith('mappings=unchanged reclaimed=1 pid-rewind=fenced')
values = {key: int(value) for key, value in re.findall(r'([a-z0-9-]+)=(\d+)', records[0])}
site = {'ata': ('ata', 1), 'nvme': ('nvme', 2), 'net': ('nic-probe', 3)}.get(sys.argv[2])
if site:
    assert values[site[0]] > 0, records
    assert lines.count(f'SMP STARTUP FIRST POLL site={site[1]} revalidated=1 completion=unchecked') == 1
print(records[0])
PY
    fi
    grep -Eq '^SMP USER TRAP seq=[0-9]+ cpu=1 slot=[0-9]+ pid=[0-9]+ epoch=[0-9]+$' "$case_log" \
        || die "$case_log has no CPU1 ring-3 trap record"
    python3 - "$case_log" "$device" > "$case_dir/pressure-oracle.log" <<'PY'
import re
import sys
from pathlib import Path

path, device = sys.argv[1:]
lines = Path(path).read_text().splitlines()
records = [line for line in lines if line.startswith('SMP USER PRESSURE ')]
assert len(records) == 1, records
fields = dict((key, int(value)) for key, value in re.findall(r'([a-z0-9-]+)=([0-9]+)', records[0]))
assert {'calls1', 'ata', 'nvme', 'nic-probe', 'nic-send', 'idle'} <= fields.keys(), records[0]
assert fields.get('calls1', 0) > 0, records[0]
if device == 'ata':
    assert fields.get('ata', 0) > 0, records[0]
elif device == 'nvme':
    assert lines.count('SMP USER DEVICE WAIT site=nvme mode=injected-first-poll revalidated=1 completion=unchecked') == 1, 'missing NVMe first-poll witness'
    assert fields.get('nvme', 0) > 0, records[0]
if device == 'net':
    assert fields.get('nic-send', 0) > 0, records[0]
    assert lines.count('SMP USER DEVICE WAIT site=nic-send mode=injected-first-poll revalidated=1 completion=unchecked') == 1
    for site in ('nic-probe', 'nic-send'):
        disposition = 'exercised' if fields[site] > 0 else 'unexercised'
        print(f"NIC {site} wait during AP pressure: {disposition} ({site}={fields[site]})")
print(records[0])
PY
}

check_success_boot() {
    case_log=$1
    test "$(grep -cx 'ABSD BOOT OK' "$case_log")" -eq 1 \
        || die "$case_log lacks exactly one successful boot record"
    check_no_failure_records "$case_log"
}

case "$mode" in
    rt-test|rt-class|block-ata|block-nvme|default)
        case_dir=$out
        case "$mode" in
            rt-test) options='rt-test smp-user-pressure'; title='ABSD RT with AP pressure' ;;
            rt-class) options='rt-class smp-user-pressure'; title='ABSD RT class with AP pressure' ;;
            block-ata|block-nvme)
                options='block-probe smp-user-pressure nvme-write=absd'
                title='ABSD block probe with AP pressure'
                truncate -s 2M "$case_dir/block.img"
                ;;
            default) options='smp-user-pressure'; title='ABSD suite with AP pressure' ;;
        esac
        if [ "$preempt" != cooperative ]; then options="$options smp-user-preempt"; fi
        if [ "$preempt" = startup ]; then options="$options smp-user-startup"; fi
        options="$options $extra_options"
        make_iso "$case_dir" "$options" "$title"
        printf 'options=%s\n' "$options" >> "$out/identity"
        printf '%s\n' running-kvm > "$out/phase"
        set --
        case "$mode" in
            block-ata)
                set -- -drive "file=$case_dir/block.img,format=raw,if=ide,index=0"
                ;;
            block-nvme)
                set -- -drive "if=none,id=nvm,file=$case_dir/block.img,format=raw" \
                    -device nvme,serial=absd,drive=nvm
                ;;
        esac
        run_pinned "$case_dir" 3 "$@"
        case "$mode" in
            rt-test)
                check_success_boot "$case_dir/serial.log"
                # Pressure consumes PID 2. Identify the sole ordinary rt-probe
                # from publication/configuration evidence rather than weaken
                # the displacement obligation or assume a replacement PID.
                normal_pid=$(python3 - "$case_dir/serial.log" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
published = {int(p) for p in re.findall(r'^SPAWN OK pid=(\d+) parent=1 program=rt-probe$', text, re.M)}
configured = {int(p) for p in re.findall(r'^RT CONFIG pid=(\d+) ', text, re.M)}
normal = published - configured
assert len(normal) == 1 and len(configured) == 2, (normal, configured)
print(normal.pop())
PY
                )
                python3 scripts/check-rt.py "$case_dir/serial.log" "$normal_pid" > "$case_dir/workload-oracle.log"
                check_pressure_records "$case_dir" none
                ;;
            rt-class)
                check_success_boot "$case_dir/serial.log"
                python3 scripts/check-rt-class.py "$case_dir/serial.log" > "$case_dir/workload-oracle.log"
                check_pressure_records "$case_dir" none
                ;;
            block-ata|block-nvme)
                backend=ata
                if [ "$mode" = block-nvme ]; then backend=nvme; fi
                check_success_boot "$case_dir/serial.log"
                grep -qx 'BLOCK DEVICE OK sectors=4096' "$case_dir/serial.log" \
                    || die 'block probe did not report 4096 sectors'
                grep -qx "BLOCK BACKEND $backend access=read-write" "$case_dir/serial.log" \
                    || die "block probe did not select writable $backend"
                python3 scripts/check-external-output.py "$case_dir/serial.log" \
                    tests/block-probe-expected.txt > "$case_dir/workload-oracle.log"
                if [ "$backend" = ata ]; then irq='[1-9][0-9]*'; else irq='[0-9]*'; fi
                grep -Eq "^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=[1-9][0-9]* block_writes=[1-9][0-9]* block_flushes=3 block_errors=[0-9]* block_waits=[0-9]* block_irqs=$irq ticks=[0-9]*$" \
                    "$case_dir/serial.log" || die 'block durable counters are incomplete'
                grep -qx 'DURABLE WORKLOAD OK' "$case_dir/serial.log" \
                    || die 'block workload did not complete'
                check_pressure_records "$case_dir" "$backend"
                ;;
            default)
                check_success_boot "$case_dir/serial.log"
                check_pressure_records "$case_dir" none
                ;;
        esac
        ;;
    net)
        case_dir=$out
        options='net-probe smp-user-pressure'
        if [ "$preempt" != cooperative ]; then options="$options smp-user-preempt"; fi
        if [ "$preempt" = startup ]; then options="$options smp-user-startup"; fi
        title='ABSD NIC probe with AP pressure'
        options="$options $extra_options"
        make_iso "$case_dir" "$options" "$title"
        printf 'options=%s\nvCPU pinning=not enforced by nic-reflect harness\n' "$options" >> "$out/identity"
        printf '%s\n' running-net-reflector > "$out/phase"
        status=0
        timeout 180s python3 scripts/nic-reflect.py "$out/reflect" "$out/serial.log" \
            qemu-system-x86_64 -accel kvm -cpu host -smp 2 -m 256M \
            -cdrom "$out/boot.iso" -display none -no-reboot -no-shutdown \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            > "$out/reflect.log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$out/reflect.status"
        test "$status" -eq 0 || die "NIC reflector status $status"
        check_success_boot "$out/serial.log"
        grep -qx 'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048' "$out/serial.log" \
            || die 'network link qualification record missing'
        grep -qx 'NIC REFUSALS OK' "$out/serial.log" || die 'NIC refusal records missing'
        grep -qx 'NIC RX REFUSED length=1515' "$out/serial.log" || die '1515-byte NIC refusal missing'
        grep -qx 'NIC RX REFUSED length=1518' "$out/serial.log" || die '1518-byte NIC refusal missing'
        grep -qx 'NIC PROBE REFLECTED frames=38 largest=1514 ignored=0 rx_frames=39 rx_refused=3 tx_frames=39' "$out/serial.log" \
            || die 'NIC reflection counters differ from the existing oracle'
        grep -qx 'NIC PROBE OK' "$out/serial.log" || die 'NIC probe workload did not complete'
        grep -qx 'NET status=0 frames=0 processes=0 cells=0 pipes=0' "$out/serial.log" \
            || die 'network workload resource census differs from the existing oracle'
        grep -qx 'NIC STATS rx_frames=39 rx_refused=3 rx_missed=0 tx_frames=39 tx_refused=5 tx_errors=0 flags=1' "$out/serial.log" \
            || die 'NIC device counters differ from the existing oracle'
        grep -qx 'NET WORKLOAD OK' "$out/serial.log" || die 'network workload did not complete'
        grep -qx 'NIC REFLECT OK frames=38 oversize_unanswered=3 mac=52:54:00:12:34:56' "$out/reflect.log" \
            || die 'NIC reflector oracle did not complete'
        check_pressure_records "$out" net
        ;;
    guards)
        for guard in ordinary rt; do
            case_dir=$out/$guard
            mkdir "$case_dir"
            if [ "$guard" = ordinary ]; then
                options=smp-ap-user-refuse
                marker='SMP AP ORDINARY RETURN REFUSAL'
            else
                options=smp-ap-rt-refuse
                marker='SMP AP RT RETURN REFUSAL'
            fi
            make_iso "$case_dir" "$options" "ABSD AP $guard return refusal"
            run_pinned "$case_dir" 11
            grep -qx "$marker" "$case_dir/serial.log" \
                || die "$guard AP return refusal marker missing"
            if grep -q 'SMP AP USER RETURN WAS NOT REFUSED' "$case_dir/serial.log"; then
                die "$guard AP return guard did not refuse"
            fi
            check_no_failure_records "$case_dir/serial.log"
        done
        ;;
esac

printf '%s\n' terminal > "$out/phase"
result=0
