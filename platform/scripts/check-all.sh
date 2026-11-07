#!/bin/sh
set -eu

# Entry refusal precedes even root resolution, inputs and cleanup traps.
case $0 in */*) entry_scripts=${0%/*} ;; *) entry_scripts=. ;; esac
"$entry_scripts/check-gate-entry.sh"
unset entry_scripts
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
campaign_root=$(dirname "$root")
. "$root/scripts/inputs.sh"

# Shell slice host composition and terminal controls (no guest).
python3 -I "$root/scripts/test_shell_packaging.py"
python3 -I "$root/scripts/test-dmesg.py"
python3 -I "$root/scripts/test-observations.py"
python3 -I "$root/scripts/test-civil-clock.py"
python3 -B -I "$root/scripts/test_sqlite_clock.py"
if [ "$ABSD_PROFILE" = full ]; then
    ABSD_AG_SOURCE=$(absd_source AG) python3 -B -I "$root/scripts/test_ag_clock.py"
    python3 -B -I "$root/scripts/test_nq_clock.py" --source "$(absd_source NQ)" \
        --work "$root/target/nq-clock-host" --target-dir "$root/target/nq-clock-host-target"
fi
python3 -I "$root/scripts/test-system-time.py" --work "$root/target/system-time-host"
python3 -I "$root/scripts/test-plain-input-read.py" --work "$root/target/plain-input-read-host"
python3 -I "$root/scripts/test-time-owner.py" --work "$root/target/time-owner-host" \
    --target-dir "$root/target/time-owner-host-target"
python3 -I "$root/scripts/tests/test_terminal_size.py"
python3 -I "$root/scripts/tests/test_prompt_mode_ack.py"
python3 -I "$root/scripts/tests/test_shell_control_poll.py"
python3 -B -I "$root/scripts/tests/test_shell_stdin_feed.py"
python3 -I "$root/scripts/tests/test_ssh_prompt_steps.py"
python3 -I "$root/scripts/tests/test_ssh_process_authority.py"
python3 -I "$root/scripts/tests/test_ssh_storage_oracle.py"
python3 -I "$root/scripts/tests/test_fsd_capacity_oracles.py"
python3 -I "$root/scripts/tests/test_fsd_probe_startup_role.py"
python3 -I "$root/scripts/tests/test_ssh_journal_objects.py"
python3 -I "$root/scripts/tests/test_served_prompt_contexts.py"
python3 -I "$root/scripts/test_operator_provenance_units.py"
canonical_kernel=$(absd_source KERNEL)
python3 -B -I "$root/scripts/test-local-ready-stream.py" --kernel "$canonical_kernel" \
    --work "$root/target/local-ready-stream-host"
# An explicit full revision selects a successor pair. The default retains
# the previous accepted pair; changing the source repository does not select
# its moving HEAD. The exact-revision check below precedes building.
kernel_commit=${ABSD_KERNEL_COMMIT:-1a44e3c207e514e1f776f3d745d62eb870d0c608}
run=
old_run=
# Shared kit source checks also run at the direct install boundary.
check_c_kit_source() {
    python3 -I "$root/scripts/c_kit_source.py" kit "$root" \
        "${ABSD_CKIT_BUILD:-$campaign_root/ckit-build}/kit"
}
# The stopped copy of the operator image the matrix builds (coordination record #67);
# cleanup() removes it on every exit, including failure and interruption.
operator_reference=
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
    if [ -n "$operator_reference" ] && [ -e "$operator_reference" ]; then
        case "$operator_reference" in
            "${TMPDIR:-/tmp}"/absd-operator-reference.*) rm -rf "$operator_reference" ;;
            *) printf '%s\n' "refusing unexpected cleanup path: $operator_reference" >&2; status=1 ;;
        esac
    fi
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
python3 "$root/scripts/test_picolibc_provenance.py"
python3 "$root/scripts/test_document_notices.py"
python3 -B -I "$root/scripts/test_gate_entry.py"
python3 -B -I "$root/scripts/test_gate_arity.py"
python3 -B -I "$root/scripts/test_toolbox_t3.py"
python3 -B -I "$root/scripts/test_rmdir_poststate.py"
python3 -B -I "$root/scripts/test_rm_host.py"
python3 -B -I "$root/scripts/test_media_profile_gate.py"
python3 -B -I "$root/scripts/test_post_kit.py"
python3 -B -I "$root/scripts/test_harness_cohort.py"
python3 "$root/scripts/test_served_kernel.py"
python3 "$root/scripts/test_served_ram.py"
python3 -B "$root/scripts/test_work_dir_guard.py"
# Frozen source identity controls use a temporary Git repo, no history/guest/build.
python3 -B -I "$root/scripts/test_storage_fence_frozen.py"
python3 -I "$root/scripts/test_c_kit_source.py"
# Census and selftest lifecycle controls use fresh host fixtures, no C-port build.
python3 -B -I "$root/scripts/c-kit-matrix-selftest.py"
python3 -B -I "$root/scripts/test_c_kit_selftest.py"
python3 -B -I "$root/scripts/test-cports-quiescence.py"
python3 -B -I "$root/scripts/test-c-kit-confirmation.py"
python3 -B -I "$root/scripts/test_c_kit_selftest_retirement.py"
# Installed SDK packaging/integrity contracts (host only; no guest or build).
python3 -B -I "$root/scripts/test_sdk.py"
# ABSD-target C compilations read no host system header (Picolibc, absd-cc,
# the kit, the cc-crate flags); build-picolibc.sh checks its real build too.
python3 -B -I "$root/scripts/test_target_host_headers.py"
# The release recipe: recorded kernel features, their replay, and the
# manifest schema (host only; fixture Makefiles, no kernel compile).
python3 "$root/scripts/test_release_manifest.py"
python3 "$root/scripts/test_public_source_identity.py"
python3 "$root/scripts/test_app_replacement_qualification.py"
python3 -I "$root/scripts/test_app_a_vm_runner.py"
# Staging receipt dispositions and exact-byte refusal controls (no guest/build).
python3 -B -I "$root/scripts/test_release_tool.py"
python3 -B -I "$root/scripts/test_preview_bundle.py"
python3 -B -I "$root/scripts/test_boot_corresponding_source.py"
python3 -B "$root/scripts/test_p2_boot_binding.py"
python3 -B "$root/scripts/test_boot_artifacts.py"
python3 -B "$root/scripts/test_operator_boot_binding.py"
python3 -B -I "$root/scripts/test_logger_boot_binding.py"
python3 -B -I "$root/scripts/test_ssh_priority_cleanup.py"
python3 -B -I "$root/scripts/test_operator_cpus.py"
python3 -B -I "$root/scripts/test_operator_build_diagnostics.py"
python3 -B -I "$root/scripts/test_operator_geometry.py"
python3 -B -I "$root/scripts/test_operator_geometry_release.py"
python3 -B -I "$root/scripts/test_operator_geometry_resume.py"
python3 -B -I "$root/scripts/test_manual.py"
python3 -B -I "$root/scripts/tests/test_process_capacity.py"
python3 -B -I "$root/scripts/test_local_console_enroll.py"
python3 -B -I "$root/scripts/tests/test_boot_operator_console.py"
python3 -B -I "$root/scripts/tests/test_boot_operator_supervisor.py"
python3 -B -I "$root/scripts/test_operator_packaging.py"
python3 -B "$root/scripts/test-qualify-operator-binding.py"
python3 -B "$root/scripts/qualification/composition/test-handoffs.py"
python3 -B -I "$root/scripts/test_fsd_regeneration.py"
python3 -B -I "$root/scripts/test_fixture_import_plan.py"
# Symbol-demand reports are written in the C locale (byte order).
python3 -I "$root/scripts/test_demand_locale.py"
python3 "$root/scripts/test_e1000_rx.py"
python3 "$root/scripts/test_ssh_owner_samples.py"
python3 "$root/scripts/test-health-observation.py" --host
python3 -B -I "$root/scripts/test-spawn-cwd.py" --work "$root/.host-target/spawn-cwd"
python3 -B -I "$root/scripts/test_media_copy.py"
# The disk installer on sparse temporary images: layout, both GPT copies,
# refusals with the target unchanged, exact-disk confirmation (docs/INSTALL-DISK.md).
python3 -B -I "$root/scripts/test_install_disk.py"
python3 -B -I "$root/scripts/test_native_installer.py"
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
# Reproducibility artifact declaration
# Both build rounds and their named receipt use these paths. No positional labels.
artifact_paths() {
    case "$ABSD_PROFILE" in
    core) printf '%s\n' \
        probe.elf exit-std.elf text-stats.elf panic-std.elf \
        fixture-import.elf broker-requester.elf broker-echo.elf netd-probe.elf \
        exec-probe.elf sh-launch.elf absd-logd.elf sshd.elf absd-sftp.elf absd-fsd.elf \
        absd-fsd-regenerate.elf absd-enroll.elf fsd-probe.elf sshtest.elf \
        commands/absd-sftp commands/absd-sh commands/cat commands/echo commands/ls \
        commands/printenv commands/pwd commands/uname commands/sh-probe \
        commands/mkdir commands/rm commands/mv commands/cp \
        commands/head commands/tail commands/wc commands/sha256sum \
        commands/stat commands/df commands/sync commands/man \
        commands/date commands/uptime commands/release commands/sysinfo \
        commands/health commands/net-status commands/terminal-size commands/sh commands/ps commands/interfaces commands/dmesg commands/logs ;;
    full) printf '%s\n' \
        probe.elf exit-std.elf text-stats.elf pulse-std.elf \
        panic-std.elf ag-authority.elf pulse-journal-std.elf ag-sqlite.elf \
        fixture-import.elf nightshift-resolver.elf nightshift-writer.elf broker-requester.elf \
        broker-echo.elf pulse-support-resolver.elf pulse-support-resolver-test.elf nq.elf \
        nq-unknown.elf nightshift-pipeline-writer.elf nightshift-ag-resolver.elf ag-loopctl-init.elf \
        ag-loopctl-record-proposal.elf nightshift-ag-resolver-short-ttl.elf netd-probe.elf exec-probe.elf \
        sh-launch.elf absd-logd.elf sshd.elf absd-sftp.elf absd-fsd.elf absd-fsd-regenerate.elf \
        absd-enroll.elf fsd-probe.elf sshtest.elf commands/absd-sftp commands/absd-sh \
        commands/cat commands/echo commands/ls commands/printenv \
        commands/pwd commands/uname commands/sh-probe commands/mkdir \
        commands/rm commands/mv commands/cp commands/head \
        commands/tail commands/wc commands/sha256sum commands/stat \
        commands/df commands/sync commands/man commands/date \
        commands/uptime commands/release commands/sysinfo commands/health \
        commands/net-status commands/terminal-size commands/sh commands/ps commands/interfaces commands/dmesg commands/logs pulse-frame-pressure-cycle.elf pulse-frame-pressure-resolver.elf pulse-frame-pressure-resolver-test.elf ;;
    *) echo 'unsupported reproducibility profile' >&2; return 1 ;;
    esac
}
artifact_hashes() {
    (
        cd "$root"
        paths=$(artifact_paths) || return
        set -- $paths
        [ "$#" -gt 0 ] || { echo "empty artifact declaration" >&2; return 1; }
        sha256sum "$@"
    )
}
artifact_summary() {
    artifact_program_count=$(artifact_paths | wc -l | tr -d ' ')
    artifact_command_count=$(artifact_paths | awk '/^commands\// {n++} END {print n+0}')
    if [ "$ABSD_PROFILE" = full ]; then
        artifact_prefix='ABSD RUST REPRODUCIBLE OK'
    else
        artifact_prefix='ABSD RUST CORE REPRODUCIBLE OK'
    fi
    printf '%s builds=2 programs=%s commands=%s' "$artifact_prefix" "$artifact_program_count" "$artifact_command_count"
    printf '%s\n' "$second_hashes" | while read -r hash path; do
        printf ' %s=%s' "$path" "$hash"
    done
    printf ' manual=%s\n' "${second_manual%% *}"
}
# End reproducibility helpers

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
# Separate from host entry: validate the existing hash-vector constants as
# soon as the first build ends, before repeating builds or starting guests.
python3 -B -I "$root/scripts/check-gate-arity.py" "$root/scripts/check-all.sh"
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
first_hashes=$(artifact_hashes)
first_manual=$(cd "$root/manpages" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
"$root/scripts/clean-owned.sh"
"$root/scripts/prepare-and-build.sh"
second_hashes=$(artifact_hashes)
test "$first_hashes" = "$second_hashes" || { echo "ABSD RUST REPRODUCIBLE FAILED: program hashes differ between builds" >&2; exit 1; }
second_manual=$(cd "$root/manpages" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
test "$first_manual" = "$second_manual" || { echo "ABSD RUST REPRODUCIBLE FAILED: manual pages differ between builds" >&2; exit 1; }
artifact_summary

run=$(mktemp -d "$campaign_root/absd-kernel-std-run.XXXXXX")
absd_kernel_run "$canonical_kernel" "$kernel_commit" "$run"
if absd_is_checkout "$canonical_kernel"; then
    test -z "$(git -C "$run" status --porcelain --untracked-files=all)"
fi
# Real kernel producer through the actual collector, private RPC and filesystem.
# The clean kernel clone above pins the source; host substitutions make no
# authorization or guest claim. Ordinary target cleanup owns these caches.
python3 -I "$root/scripts/test-journal-source-admission.py" --kernel "$run" \
    --work "$root/target/log-source-admission" --target-dir "$root/target/log-source-admission-target"
python3 -I "$root/scripts/test-journal-source-admission.py" --kernel "$run" \
    --work "$root/target/log-recovery" --target-dir "$root/target/log-source-admission-target" --scenario recovery
# Actual local init relay/publication through this pair's unchanged host readers.
python3 -B -I "$run/scripts/test-local-console-startup.py" --platform "$root"
# The runtime's hand-copied syscall table is generation
# absd_release::KERNEL_ABI; every program refuses (status 103) a kernel that
# answers abi_version (42) with anything else.
release_abi=$(sed -n 's/^pub const KERNEL_ABI: u32 = \([0-9][0-9]*\);$/\1/p' "$root/release/src/lib.rs")
python3 -B -I "$root/scripts/check-wait-readable-contract.py" --kernel "$run"
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
ABSD_KERNEL_RUN=$run python3 -I "$root/scripts/tests/test_check_abi_compiler_facts.py"

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
check_c_kit_source
sh "$root/scripts/build-userland.sh"
check_c_kit_source
# Post-kit, separate from cheap entry checks: use the existing installer's
# output and original context/digest predicates before building Rust ports.
python3 -B -I "$root/scripts/check-post-kit.py" "$root"
"$root/scripts/build-ports.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-cmds-matrix.sh"
# The kit's own gate (clang and gcc builds, the embedded and shell matrices)
# stays in the full profile.
extended env ABSD_KERNEL_RUN="$run" ABSD_SKIP_BUILD=0 ABSD_C_GCC=1 "$root/scripts/run-c-kit.sh"
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 "$root/scripts/run-perf-matrix.sh"
operator_reference=$(mktemp -d "${TMPDIR:-/tmp}/absd-operator-reference.XXXXXX")
ABSD_KERNEL_RUN=$run ABSD_SKIP_BUILD=1 ABSD_OPERATOR_REFERENCE=$operator_reference "$root/scripts/run-operator-matrix.sh"
# The candidate-media builder (scripts/media.py): host tests plus the
# end-to-end refusals, which assemble real images with the pinned image
# tools (no compiler, no QEMU). The S4 classes need the private S4
# candidate; without it the last line lists each skip and its reason, and
# ABSD_REQUIRE_S4=1 turns any skip into a failure. Its operator-disk case and
# absd-try's real-reader cases read the stopped copy of the image the operator
# matrix just built (coordination record #67): never a protected endurance guest's disk.
ABSD_MEDIA_E2E=1 ABSD_U1B_IMAGE=$operator_reference python3 -I "$root/scripts/test_media.py"
ABSD_TRY_REAL_DISK=$operator_reference/absd-operator.img python3 -I "$root/scripts/test_absd_try.py"
rm -rf "${operator_reference:?}"
operator_reference=
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
    printf '%s\n' "ABSD RUST STD MATRIX OK programs=$artifact_program_count kernel=$kernel_identity observe_old_kernel=$observe_old_kernel ag_native=$ag_native"
else
    printf '%s\n' "ABSD RUST STD CORE MATRIX OK kernel=$kernel_identity extended=NOT_RUN steps=$(set -- $not_run; echo $#):$(echo $not_run | tr ' ' ,)"
fi
