#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

# Plain removal: `cargo clean` in the integration workspace would need the
# staged AG and Pulse trees to resolve.
rm -rf "$root/target" "$root/integration/target"
rm -rf "$root/.staged-sysroot" "$root/.host-target" "$root/.durable-work" "$root/.fs-work" \
    "$root/.broker-work" "$root/.exec-work" "$root/commands" "$root/.net-work" "$root/manpages"
rm -rf "$(dirname "$root")/absd-std-staged-ag" "$(dirname "$root")/absd-std-staged-nightshift" \
    "$(dirname "$root")/absd-std-nightshift-linux" "$root/.nightshift-work" \
    "$(dirname "$root")/absd-std-staged-pulse" "$(dirname "$root")/absd-std-pulse-linux" "$root/.pulse-work" \
    "$(dirname "$root")/absd-std-staged-nq" "$(dirname "$root")/absd-std-nq-linux" "$root/.nq-work" \
    "$(dirname "$root")/absd-std-staged-ag-loopctl" "$root/.ag-native-work" \
    "$(dirname "$root")/absd-std-staged-pulse-observe" "$root/.observe-work" \
    "$(dirname "$root")/absd-std-staged-pulse-source"
rm -f "$root/probe.elf" "$root/pulse-std.elf" "$root/exit-std.elf" \
    "$root/text-stats.elf" "$root/panic-std.elf" "$root/ag-authority.elf" \
    "$root/pulse-journal-std.elf" "$root/ag-sqlite.elf" "$root/fixture-import.elf" \
    "$root/nightshift-resolver.elf" "$root/nightshift-writer.elf" "$root/nightshift-pipeline-writer.elf" \
    "$root/broker-requester.elf" "$root/broker-echo.elf" "$root/netd-probe.elf" \
    "$root/pulse-support-resolver.elf" "$root/pulse-support-resolver-test.elf" \
    "$root/nq.elf" "$root/nq-unknown.elf" "$root/nq-profile-digest.txt" \
    "$root/nightshift-ag-resolver.elf" "$root/nightshift-ag-resolver-short-ttl.elf" "$root/ag-loopctl-init.elf" "$root/ag-loopctl-record-proposal.elf" \
    "$root/exec-probe.elf" "$root/sh-launch.elf" "$root/sshd.elf" "$root/absd-fsd.elf" "$root/absd-fsd-regenerate.elf" \
    "$root/sshtest.elf" "$root/.pulse-host-report.json" \
    "$root/pulse-frame-pressure-cycle.elf" "$root/pulse-frame-pressure-resolver.elf" \
    "$root/pulse-frame-pressure-resolver-test.elf"
rm -rf "$root/ssh/target" "$root/scripts/__pycache__"
rm -rf "$root/compat-commands" "$root/compat-linux" "$root/ports"
rm -f "$root/compat-launch.elf" "$root/fsd-probe.elf"
rm -rf "$root/.operator-work" "$root/.operator-work.log" "$root/.host-target-ssh"
rm -rf "$root/.contain-build" "$root/.contain-work"
