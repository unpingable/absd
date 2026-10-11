#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
campaign_root=$(dirname "$root")
. "$root/scripts/inputs.sh"
canonical_kernel=$(absd_source KERNEL)
# An explicit full revision selects a successor pair. The default retains
# the previous accepted pair; changing the source repository does not select
# its moving HEAD. The exact-revision check below precedes building.
kernel_commit=${ABSD_KERNEL_COMMIT:-260b4a20755a70db2ec8aa4556b9c576285fe284}
run=
old_run=
# A kernel before frame_stats (syscall 35): the observation matrix's
# "kernel refuses, answer unknown" case.
old_kernel_commit=bc97503a9aaad7dfe4f9187abe3157c6c88b6bfd
worst_new_bytes=2147483648
reserve_bytes=10737418240

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    "$root/scripts/clean-owned.sh" || status=1
    for clone in "$run" "$old_run"; do
        if [ -n "$clone" ] && [ -e "$clone" ]; then
            case "$clone" in
                "$campaign_root"/absd-kernel-std-run.*) rm -rf "$clone" ;;
                *) printf '%s\n' "refusing unexpected cleanup path: $clone" >&2; status=1 ;;
            esac
        fi
    done
    allocated=$(du -s -B1 "$root" | awk '{print $1}')
    printf 'ABSD RUST CLEANUP allocated=%s qemu=' "$allocated"
    # Only this run's guests: other VMs on the host are not ours to judge.
    if ps -eo args= | awk -v run="$campaign_root" '$1 ~ /qemu-system/ && index($0, run) {found=1} END {exit !found}'; then
        printf '%s\n' present
        status=1
    else
        printf '%s\n' none
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

current_bytes=$(du -s -B1 "$root" | awk '{print $1}')
available_bytes=$(df -B1 --output=avail "$root" | awk 'NR == 2 {print $1}')
required_bytes=$((worst_new_bytes + reserve_bytes))
printf '%s\n' \
    "ABSD RUST STORAGE current=$current_bytes failed_retained=0 worst_new=$worst_new_bytes available=$available_bytes reserve=$reserve_bytes"
test "$available_bytes" -ge "$required_bytes"

# Third-party material, licences and the dependency inventory against the
# recorded baseline (docs/PROVENANCE.md). Fast; builds nothing.
"$root/scripts/provenance.py" check
python3 "$root/scripts/test_provenance.py"
# A kernel checkout must hold the exact revision. A kernel snapshot (a plain
# directory, as in a source release) has no revision to test: it must be the
# tree the release's manifest names, unless ABSD_ALLOW_MODIFIED=1 says a
# modified tree is being tested, and the last line says which it was.
kernel_identity=commit
observe_old_kernel=run
ag_native=run

# The two profiles (scripts/inputs.sh). `full` is this gate as it has always
# been. `core` is the part that needs nothing but ABSD: every step that
# builds or runs another project's code is named NOT_RUN, the builds
# compared are the core programs only, and the last line is a different
# one, so a core run can never be read as the full gate.
case ${absd_profile_reason:-} in
'') absd_profile_reason=unknown ;;
esac
printf '%s\n' "ABSD PROFILE $ABSD_PROFILE reason=$absd_profile_reason"
not_run=
extended() {
    if [ "$ABSD_PROFILE" = full ]; then
        "$@"
    else
        for absd_step in "$@"; do :; done
        absd_step=$(basename "$absd_step" .sh)
        printf '%s\n' "ABSD EXTENDED NOT_RUN step=$absd_step profile=core"
        not_run="$not_run $absd_step"
    fi
}
# The core programs whose two builds are compared.
core_hashes() {
    sha256sum \
        "$root/probe.elf" "$root/exit-std.elf" "$root/text-stats.elf" "$root/panic-std.elf" \
        "$root/fixture-import.elf" "$root/broker-requester.elf" "$root/broker-echo.elf" \
        "$root/netd-probe.elf" "$root/exec-probe.elf" "$root/sh-launch.elf" "$root/sshd.elf" \
        "$root/absd-fsd.elf" "$root/absd-fsd-regenerate.elf" "$root/fsd-probe.elf" "$root/sshtest.elf" \
        "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
        "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
        "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
        "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
        "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
        "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
        "$root"/commands/sysinfo |
        awk '{print $1}'
}
if absd_is_checkout "$canonical_kernel"; then
    test "$(git -C "$canonical_kernel" rev-parse "$kernel_commit^{commit}")" = "$kernel_commit"
else
    test -f "$canonical_kernel/Makefile"
    kernel_identity=$(absd_kernel_identity "$canonical_kernel")
    printf '%s\n' "ABSD KERNEL IDENTITY source=$canonical_kernel identity=$kernel_identity (from the source manifest)"
fi
"$root/scripts/clean-owned.sh"
"$root/scripts/verify-inputs.sh"
extended "$root/scripts/check-pulse-oracle.sh"

"$root/scripts/prepare-and-build.sh"
# The filesystem library against a host sector device: every crash point
# of every operation, corruption refusal, identity, locks, ENOSPC.
(cd "$root/fs" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-fs)
printf '%s\n' 'ABSD FS HOST TESTS OK'
# The release record and the compiled identity (docs/RELEASE.md).
(cd "$root/release" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-release)
printf '%s\n' 'ABSD RELEASE HOST TESTS OK'
# The broker wire codecs: startup record, requests, replies, demultiplexing.
(cd "$root/broker" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-broker)
printf '%s\n' 'ABSD BROKER HOST TESTS OK'
# The runtime allocator with a bounded local page arena, without installing
# the ABSD runtime as the host's global allocator.
"$root/scripts/check-runtime-allocator.sh"
# The file server's protocol, mount lists, and dispatcher.
(cd "$root/fsd" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-fsd)
printf '%s\n' 'ABSD FSD HOST TESTS OK'
# absd-sh's parser and builtins (its own workspace; the binary includes it).
(cd "$root/sh" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target")
printf '%s\n' 'ABSD SH HOST TESTS OK'
# The network stack wrapper: two stacks over an in-memory wire.
(cd "$root/net" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-net)
printf '%s\n' 'ABSD NET HOST TESTS OK'
# sshd's /etc readers, exec forms, control codec, and line discipline (its
# own workspace and lock, built for Linux).
(cd "$root/ssh" && env -u RUSTFLAGS cargo +1.95.0 test --offline --locked --release \
    --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target-ssh")
printf '%s\n' 'ABSD SSHD HOST TESTS OK'
if [ "$ABSD_PROFILE" = full ]; then
first_hashes=$(sha256sum \
    "$root/probe.elf" "$root/exit-std.elf" "$root/text-stats.elf" \
    "$root/pulse-std.elf" "$root/panic-std.elf" \
    "$root/ag-authority.elf" "$root/pulse-journal-std.elf" "$root/ag-sqlite.elf" \
    "$root/fixture-import.elf" "$root/nightshift-resolver.elf" "$root/nightshift-writer.elf" \
    "$root/broker-requester.elf" "$root/broker-echo.elf" \
    "$root/pulse-support-resolver.elf" "$root/pulse-support-resolver-test.elf" \
    "$root/nq.elf" "$root/nq-unknown.elf" "$root/nightshift-pipeline-writer.elf" \
    "$root/nightshift-ag-resolver.elf" "$root/ag-loopctl-init.elf" "$root/ag-loopctl-record-proposal.elf" \
    "$root/nightshift-ag-resolver-short-ttl.elf" "$root/netd-probe.elf" \
    "$root/exec-probe.elf" "$root/sh-launch.elf" "$root/sshd.elf" "$root/absd-fsd.elf" \
    "$root/absd-fsd-regenerate.elf" "$root/fsd-probe.elf" \
    "$root/sshtest.elf" "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
    "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
    "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
    "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
    "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
    "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
    "$root"/commands/sysinfo \
    "$root/pulse-frame-pressure-cycle.elf" "$root/pulse-frame-pressure-resolver.elf" \
    "$root/pulse-frame-pressure-resolver-test.elf" |
    awk '{print $1}')
else
    first_hashes=$(core_hashes)
fi
first_manual=$(cd "$root/manpages" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
"$root/scripts/clean-owned.sh"
"$root/scripts/prepare-and-build.sh"
if [ "$ABSD_PROFILE" = full ]; then
second_hashes=$(sha256sum \
    "$root/probe.elf" "$root/exit-std.elf" "$root/text-stats.elf" \
    "$root/pulse-std.elf" "$root/panic-std.elf" \
    "$root/ag-authority.elf" "$root/pulse-journal-std.elf" "$root/ag-sqlite.elf" \
    "$root/fixture-import.elf" "$root/nightshift-resolver.elf" "$root/nightshift-writer.elf" \
    "$root/broker-requester.elf" "$root/broker-echo.elf" \
    "$root/pulse-support-resolver.elf" "$root/pulse-support-resolver-test.elf" \
    "$root/nq.elf" "$root/nq-unknown.elf" "$root/nightshift-pipeline-writer.elf" \
    "$root/nightshift-ag-resolver.elf" "$root/ag-loopctl-init.elf" "$root/ag-loopctl-record-proposal.elf" \
    "$root/nightshift-ag-resolver-short-ttl.elf" "$root/netd-probe.elf" \
    "$root/exec-probe.elf" "$root/sh-launch.elf" "$root/sshd.elf" "$root/absd-fsd.elf" \
    "$root/absd-fsd-regenerate.elf" "$root/fsd-probe.elf" \
    "$root/sshtest.elf" "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
    "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
    "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
    "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
    "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
    "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
    "$root"/commands/sysinfo \
    "$root/pulse-frame-pressure-cycle.elf" "$root/pulse-frame-pressure-resolver.elf" \
    "$root/pulse-frame-pressure-resolver-test.elf" |
    awk '{print $1}')
else
    second_hashes=$(core_hashes)
fi
test "$first_hashes" = "$second_hashes"
second_manual=$(cd "$root/manpages" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
test "$first_manual" = "$second_manual"
set -- $second_hashes
if [ "$ABSD_PROFILE" = full ]; then
test "$#" -eq 57
printf '%s\n' \
    "ABSD RUST REPRODUCIBLE OK builds=2 probe=$1 exit=$2 text=$3 pulse=$4 panic=$5 ag=$6 journal=$7 sqlite=$8 import=$9 resolver=${10} writer=${11} requester=${12} echo=${13} support=${14} support_test=${15} nq=${16} nq_unknown=${17} pipeline=${18} ag_resolver=${19} ag_init=${20} ag_record=${21} ag_resolver_short=${22} netd=${23} exec=${24} sh_launch=${25} sshd=${26} fsd=${27} fsd_regenerate=${28} commands=24 manual=${second_manual%% *}"
else
    test "$#" -eq 39
    printf '%s\n' "ABSD RUST CORE REPRODUCIBLE OK builds=2 programs=$# commands=24 manual=${second_manual%% *}"
fi

run=$(mktemp -d "$campaign_root/absd-kernel-std-run.XXXXXX")
absd_kernel_run "$canonical_kernel" "$kernel_commit" "$run"
if absd_is_checkout "$canonical_kernel"; then
    test -z "$(git -C "$run" status --porcelain --untracked-files=all)"
fi
# The runtime's hand-copied syscall table is generation
# absd_release::KERNEL_ABI; every program refuses (status 103) a kernel that
# answers abi_version (42) with anything else.
release_abi=$(sed -n 's/^pub const KERNEL_ABI: u32 = \([0-9][0-9]*\);$/\1/p' "$root/release/src/lib.rs")
grep -qx "pub const KERNEL_ABI: u64 = $release_abi;" "$run/abi/src/lib.rs" || \
    { echo "check-all: kernel $kernel_commit is not syscall ABI generation $release_abi" >&2; exit 1; }

ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-probe.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-exit.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-text-stats.sh"
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=1 "$root/scripts/run-pulse.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-panic.sh"
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=1 "$root/scripts/run-ag-authority.sh"
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=1 "$root/scripts/run-pulse-journal.sh"
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=1 "$root/scripts/run-fs-matrix.sh"
extended env ABSD_KERNEL_RUN="$run" "$root/scripts/run-nightshift-matrix.sh"
extended env ABSD_KERNEL_RUN="$run" "$root/scripts/run-nq-matrix.sh"
extended env ABSD_KERNEL_RUN="$run" "$root/scripts/run-pulse-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-broker.sh"
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=1 "$root/scripts/run-pipeline-matrix.sh"
# The AG twin compares the native run with Linux programs pinned by digest
# (fixtures/ag-native/manifest.json). A source release cannot carry them, so
# there, and only there, their absence skips this one matrix, by name.
if [ "$ABSD_PROFILE" != full ]; then
    extended "$root/scripts/run-ag-native.sh"
    ag_native=not-run
elif [ -f "$absd_release_manifest" ] && [ ! -x "$ABSD_REFERENCE_LINUX/bin/ag-loopctl" ]; then
    printf '%s\n' "ABSD AG NATIVE SKIPPED reason=no-linux-reference (set ABSD_REFERENCE_LINUX to run it)"
    ag_native=skipped
else
    ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-ag-native.sh"
fi
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-exec-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-sh-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-net-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-ssh-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-fsd-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-served-matrix.sh"
"$root/scripts/build-ports.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-cmds-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-perf-matrix.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-operator-matrix.sh"
# Session containment (E2) runs under KVM: its churn and race columns are
# hundreds of sessions, and this is the matrices' KVM column.
ABSD_CONTAIN_ACCEL=kvm ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-contain-matrix.sh"
if [ "$ABSD_PROFILE" != full ]; then
    extended "$root/scripts/run-observe-matrix.sh"
    observe_old_kernel=not-run
elif absd_is_checkout "$canonical_kernel"; then
    old_run=$(mktemp -d "$campaign_root/absd-kernel-std-run.XXXXXX")
    absd_kernel_run "$canonical_kernel" "$old_kernel_commit" "$old_run"
    ABSD_KERNEL_RUN=$run ABSD_KERNEL_OLD_RUN=$old_run ABSD_OBSERVE_SKIP_UNAVAILABLE=0 "$root/scripts/run-observe-matrix.sh"
else
    # A snapshot holds one kernel, so the earlier kernel cannot be made:
    # that one case is skipped, by name, and the rest of the matrix runs.
    ABSD_KERNEL_RUN=$run ABSD_OBSERVE_SKIP_UNAVAILABLE=1 "$root/scripts/run-observe-matrix.sh"
    observe_old_kernel=skipped
fi
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-compat-probe.sh"
if [ "$ABSD_PROFILE" = full ]; then
    printf '%s\n' "ABSD RUST STD MATRIX OK programs=56 kernel=$kernel_identity observe_old_kernel=$observe_old_kernel ag_native=$ag_native"
else
    printf '%s\n' "ABSD RUST STD CORE MATRIX OK kernel=$kernel_identity extended=NOT_RUN steps=$(set -- $not_run; echo $#):$(echo $not_run | tr ' ' ,)"
fi
