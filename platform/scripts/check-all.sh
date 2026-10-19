#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
campaign_root=$(dirname "$root")
. "$root/scripts/inputs.sh"
canonical_kernel=$(absd_source KERNEL)
# An explicit full revision selects a successor pair. The default retains
# the previous accepted pair; changing the source repository does not select
# its moving HEAD. The exact-revision check below precedes building.
kernel_commit=${ABSD_KERNEL_COMMIT:-aee59ea40a0a062dc1c45a30055a8a3b3cf98ffd}
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
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
python3 "$root/scripts/test_served_kernel.py"
python3 "$root/scripts/test_served_ram.py"
# The release recipe: recorded kernel features, their replay, and the
# manifest schema (host only; fixture Makefiles, no kernel compile).
python3 "$root/scripts/test_release_manifest.py"
# Staging receipt dispositions and exact-byte refusal controls (no guest/build).
python3 -B -I "$root/scripts/test_release_tool.py"
# Symbol-demand reports are written in the C locale (byte order).
python3 -I "$root/scripts/test_demand_locale.py"
python3 "$root/scripts/test_e1000_rx.py"
python3 "$root/scripts/test_ssh_owner_samples.py"
python3 "$root/scripts/test-health-observation.py" --host
# The candidate-media builder (scripts/media.py): host tests plus the
# end-to-end refusals, which assemble real images with the pinned image
# tools (no compiler, no QEMU). The S4 classes need the private S4
# candidate; without it the last line lists each skip and its reason, and
# ABSD_REQUIRE_S4=1 turns any skip into a failure.
python3 -B -I "$root/scripts/test_media_copy.py"
ABSD_MEDIA_E2E=1 python3 -I "$root/scripts/test_media.py"
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
        "$root/absd-fsd.elf" "$root/absd-fsd-regenerate.elf" "$root/absd-enroll.elf" "$root/fsd-probe.elf" "$root/sshtest.elf" \
        "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
        "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
        "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
        "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
        "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
        "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
        "$root"/commands/sysinfo "$root"/commands/health "$root"/commands/net-status |
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
# SPEC A21 (R12): the runtime decoder and std's FileAttr conversion refuse
# a file server kind outside 1..=2 (host tests; the sites are held statically
# by check-fs-kinds.py itself).
python3 -I "$root/scripts/check-fs-kinds.py" "$root" --exercise
python3 -I "$root/scripts/check-mtime.py" "$root" --self-test
python3 -I "$root/scripts/test_mtime_listing.py"
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
    "$root/absd-fsd-regenerate.elf" "$root/absd-enroll.elf" "$root/fsd-probe.elf" \
    "$root/sshtest.elf" "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
    "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
    "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
    "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
    "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
    "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
    "$root"/commands/sysinfo "$root"/commands/health "$root"/commands/net-status \
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
    "$root/absd-fsd-regenerate.elf" "$root/absd-enroll.elf" "$root/fsd-probe.elf" \
    "$root/sshtest.elf" "$root"/commands/absd-sh "$root"/commands/cat "$root"/commands/echo \
    "$root"/commands/ls "$root"/commands/printenv "$root"/commands/pwd "$root"/commands/uname \
    "$root"/commands/sh-probe "$root"/commands/mkdir "$root"/commands/rm "$root"/commands/mv \
    "$root"/commands/cp "$root"/commands/head "$root"/commands/tail "$root"/commands/wc \
    "$root"/commands/sha256sum "$root"/commands/stat "$root"/commands/df "$root"/commands/sync \
    "$root"/commands/man "$root"/commands/date "$root"/commands/uptime "$root"/commands/release \
    "$root"/commands/sysinfo "$root"/commands/health "$root"/commands/net-status \
    "$root/pulse-frame-pressure-cycle.elf" "$root/pulse-frame-pressure-resolver.elf" \
    "$root/pulse-frame-pressure-resolver-test.elf" |
    awk '{print $1}')
else
    second_hashes=$(core_hashes)
fi
test "$first_hashes" = "$second_hashes" || { echo "ABSD RUST REPRODUCIBLE FAILED: program hashes differ between builds" >&2; exit 1; }
second_manual=$(cd "$root/manpages" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
test "$first_manual" = "$second_manual" || { echo "ABSD RUST REPRODUCIBLE FAILED: manual pages differ between builds" >&2; exit 1; }
set -- $second_hashes
if [ "$ABSD_PROFILE" = full ]; then
test "$#" -eq 60 || { echo "ABSD RUST REPRODUCIBLE FAILED: hashed $# files, expected 60" >&2; exit 1; }
printf '%s\n' \
    "ABSD RUST REPRODUCIBLE OK builds=2 probe=$1 exit=$2 text=$3 pulse=$4 panic=$5 ag=$6 journal=$7 sqlite=$8 import=$9 resolver=${10} writer=${11} requester=${12} echo=${13} support=${14} support_test=${15} nq=${16} nq_unknown=${17} pipeline=${18} ag_resolver=${19} ag_init=${20} ag_record=${21} ag_resolver_short=${22} netd=${23} exec=${24} sh_launch=${25} sshd=${26} fsd=${27} fsd_regenerate=${28} commands=26 manual=${second_manual%% *}"
else
    test "$#" -eq 42 || { echo "ABSD RUST CORE REPRODUCIBLE FAILED: hashed $# files, expected 42" >&2; exit 1; }
    printf '%s\n' "ABSD RUST CORE REPRODUCIBLE OK builds=2 programs=$# commands=26 manual=${second_manual%% *}"
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
# The kernel facts this tree copies by hand (loader segment cap, image
# window, spawn image cap, heap window, map cap) against this kernel's
# source: OK, MISMATCH (exit 1) or UNKNOWN (exit 2, never OK); a stricter
# copy is named NARROWER. Then the ELF gate's own host tests, kernel mode
# included.
python3 -I "$run/scripts/check-frame-admission.py" --platform "$root" \
    --platform-contract "$root/scripts/frame-admission-v0.toml"
python3 -I "$run/scripts/check-frame-admission.py" --self-test
python3 -I "$root/scripts/check-abi-elf.py" --kernel "$run" --root "$root"
ABSD_KERNEL_RUN=$run python3 -I "$root/scripts/tests/test_check_abi_elf.py"

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
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-core-fsd-recovery.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-served-matrix.sh"
# The base userland's sbase ports (userland/README.md) are C programs built
# through the C kit, so the kit (pinned Picolibc, host clang) is a core
# input from here on: build-ports.sh installs them at their pinned digests
# (docs/base-userland-20261012/RECORD.md, "Gate on merge (I1)").
sh "$root/scripts/build-picolibc.sh"
sh "$root/scripts/build-c-kit.sh"
sh "$root/scripts/build-userland.sh"
"$root/scripts/build-ports.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-cmds-matrix.sh"
# The kit's own gate (clang and gcc builds, the embedded and shell matrices)
# stays in the full profile.
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=0 ABSD_C_GCC=1 "$root/scripts/run-c-kit.sh"
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
