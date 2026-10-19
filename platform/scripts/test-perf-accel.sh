#!/bin/sh
# Self-test of the perf matrix's accelerator selection (scripts/perf-accel.sh)
# and of its refusal before any work: run-perf-matrix.sh is invoked with a
# kernel path that does not exist, so a selection that is accepted fails
# later at the kernel check (exit 1), and a refused one exits 2 first.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fail() { echo "PERF ACCEL TEST FAILED: $*" >&2; exit 1; }
resolve() { (env -u ABSD_PERF_ACCEL -u ABSD_QEMU "$@" sh -c ". '$root/scripts/perf-accel.sh'; printf '%s|%s' \"\$accel\" \"\$qemu\"") 2>/dev/null; }
[ "$(resolve)" = "tcg|qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" ] || fail "default: $(resolve)"
[ "$(resolve ABSD_PERF_ACCEL=tcg)" = "tcg|qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" ] || fail "explicit tcg"
[ "$(resolve ABSD_QEMU=/opt/qemu/bin/qemu-system-x86_64)" = "tcg|/opt/qemu/bin/qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" ] || fail "ABSD_QEMU binary"
run() { status=0; env -u ABSD_PERF_ACCEL -u ABSD_QEMU ABSD_KERNEL_RUN=/nonexistent/absd-kernel-run ABSD_SKIP_BUILD=1 "$@" sh "$root/scripts/run-perf-matrix.sh" >/dev/null 2>&1 || status=$?; echo $status; }
[ "$(run ABSD_PERF_ACCEL=bogus)" = 2 ] || fail "invalid selector not refused first"
[ "$(run ABSD_QEMU='qemu-system-x86_64 -accel kvm')" = 2 ] || fail "accelerator in ABSD_QEMU not refused"
[ "$(run ABSD_QEMU='qemu-system-x86_64 -machine q35,accel=kvm')" = 2 ] || fail "machine accel= in ABSD_QEMU not refused"
[ "$(run ABSD_PERF_ACCEL=kvm ABSD_KVM_DEVICE=/nonexistent/kvm)" = 2 ] || fail "missing KVM device not refused first"
[ "$(run ABSD_PERF_ACCEL=kvm ABSD_KVM_DEVICE=/dev/null)" = 2 ] || fail "a non-KVM device not refused first"
[ "$(run ABSD_PERF_ACCEL=tcg)" = 1 ] || fail "tcg should pass selection and stop at the kernel check"
kvm=not-checked
if [ -c /dev/kvm ] && [ "$(resolve ABSD_PERF_ACCEL=kvm | cut -d'|' -f1)" = kvm ]; then
    [ "$(resolve ABSD_PERF_ACCEL=kvm)" = "kvm|qemu-system-x86_64 -accel kvm -cpu host" ] || fail "kvm words"
    [ "$(run ABSD_PERF_ACCEL=kvm)" = 1 ] || fail "usable kvm should pass selection and stop at the kernel check"
    kvm=usable
fi
# A failing matrix must fail the wrapper (no tee masking), with or without
# ABSD_PERF_RECORD: a stub tree whose perf-matrix.py prints and exits 3.
stub=$(mktemp -d); trap 'rm -rf "$stub"' EXIT
mkdir -p "$stub/scripts" "$stub/commands" "$stub/perf" "$stub/kernel"
cp "$root/scripts/run-perf-matrix.sh" "$root/scripts/perf-accel.sh" "$stub/scripts/"
printf '%s\n' 'absd_not_kernel_source() { :; }' > "$stub/scripts/inputs.sh"
printf '%s\n' 'print("FSD THROUGHPUT OK before=1"); print("COMMAND START OK native=1"); raise SystemExit(3)' > "$stub/scripts/perf-matrix.py"
for f in sshd.elf absd-fsd.elf sshtest.elf fsd-probe.elf fixture-import.elf commands/absd-sh Makefile; do : > "$stub/$f"; done
: > "$stub/kernel/Makefile"; echo '{}' > "$stub/perf/baseline.json"
for record in "" "$stub/record.json"; do
    status=0
    out=$(env -u ABSD_PERF_ACCEL -u ABSD_QEMU ABSD_KERNEL_RUN="$stub/kernel" ABSD_SKIP_BUILD=1 ABSD_PERF_RECORD="$record" \
        sh "$stub/scripts/run-perf-matrix.sh" 2>&1) || status=$?
    [ "$status" = 3 ] || fail "a failing matrix exited $status (record='$record'), not 3"
    case $out in *"ABSD RUST PERF OK"*) fail "OK printed after a failed matrix (record='$record')" ;; esac
done
echo "PERF ACCEL TEST OK cases=$([ $kvm = usable ] && echo 13 || echo 11) kvm=$kvm"
