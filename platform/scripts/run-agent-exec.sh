#!/bin/sh
# The agent execution run (scripts/agent-exec.py): the driver's self-test,
# then one `net fsd` boot of sshd under QEMU and the case file's calls
# (docs/agent-exec-20261012/cases.tsv), each one SSH exec session, with a
# receipt per call. Builds nothing: the boot ELFs, commands and the manual
# must already be built (scripts/prepare-and-build.sh, scripts/build-ssh.sh,
# scripts/render-man.sh); mkdir is required (cases C3a and C4).
# Environment: ABSD_KERNEL_RUN (required; a disposable kernel copy, never
# the protected kernel source or a kernel source checkout); ABSD_QEMU (default
# qemu-system-x86_64); ABSD_AGENT_EXEC_CANDIDATE=2 also runs the rows marked
# `# requires candidate 2` (C12: needs /bin/tcc and the tcc fixture image,
# which this script does not provide); ABSD_AGENT_EXEC_BASELINE=after-first
# compares capacity with the first call's after-line instead of the boot's
# first quiescent line; ABSD_AGENT_EXEC_WORK (default
# <platform>/.agent-exec-work); ABSD_AGENT_JOBS="FILE..." also runs those
# job files (scripts/agent-job.py, docs/agent-exec-20261012/JOB.md) in a
# second boot after the case run, and ABSD_AGENT_EXEC_SKIP_CASES=1 runs only
# the jobs. Each boot is one QEMU, one after the other.
# Host rules, enforced here: the script re-executes itself under nice so it
# runs at niceness 10 or more; it refuses to start when the 1-minute load is
# above 10; it holds a lock so only one run of this lane exists, and refuses
# to start while any QEMU already runs from its work directory (one QEMU of
# this lane at a time).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel copy}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=${ABSD_AGENT_EXEC_WORK:-$root/.agent-exec-work}
candidate=${ABSD_AGENT_EXEC_CANDIDATE:-0}
baseline=${ABSD_AGENT_EXEC_BASELINE:-first}

# The work directory is removed whole at start: only a directory of this
# lane's own name, never a path with `..`, `.` or an empty component.
case "$work" in
    /*) ;;
    *) echo "run-agent-exec: ABSD_AGENT_EXEC_WORK must be absolute: $work" >&2; exit 1 ;;
esac
case "$work" in
    */../*|*/..|*/./*|*/.|*//*|*/) echo "run-agent-exec: refusing work directory $work" >&2; exit 1 ;;
esac
case "$(basename -- "$work")" in
    .agent-exec-work|.agent-exec-work-*) ;;
    *) echo "run-agent-exec: the work directory's name must be .agent-exec-work or .agent-exec-work-*: $work" >&2; exit 1 ;;
esac
if [ -e "$work" ] && { [ -L "$work" ] || ! [ -d "$work" ]; }; then
    echo "run-agent-exec: $work exists and is not a plain directory" >&2; exit 1
fi
[ -d "$kernel" ] || { echo "run-agent-exec: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-agent-exec: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }
. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"

niceness=$(nice)
[ "$niceness" -ge 10 ] || exec nice -n $((10 - niceness)) sh "$0" "$@"
load=$(cut -d' ' -f1 /proc/loadavg)
awk -v l="$load" 'BEGIN { exit !(l <= 10) }' ||
    { echo "run-agent-exec: the 1-minute load is $load (above 10): not starting" >&2; exit 1; }

mkdir -p "$(dirname "$work")"
exec 9>"$work.lock"
flock -n 9 || { echo "run-agent-exec: another run holds $work.lock" >&2; exit 1; }
if pgrep -f "qemu-system.*$work/" >/dev/null 2>&1; then
    pgrep -af "qemu-system.*$work/" >&2
    echo "run-agent-exec: a QEMU of this lane is already running" >&2; exit 1
fi

for file in sshd.elf absd-fsd.elf absd-fsd-regenerate.elf sshtest.elf fsd-probe.elf fixture-import.elf \
        commands/absd-sh commands/mkdir manpages/whatis; do
    test -f "$root/$file" ||
        { echo "run-agent-exec: $file missing: run prepare-and-build.sh, build-ssh.sh and render-man.sh" >&2; exit 1; }
done

# The kernel stamp: what the copy says it is (.absd-identity, written by
# scripts/inputs.sh or whoever made the copy), else its own HEAD only when it
# is a checkout. A copy with neither is `unknown`: `git -C` on a directory
# without .git walks up to an enclosing repository and prints that one's HEAD.
# (agent-exec.py --self-test runs this function between the markers.)
# BEGIN kernel_stamp
kernel_stamp() {
    if [ -f "$1/.absd-identity" ]; then
        head -n 1 "$1/.absd-identity"
    elif [ -e "$1/.git" ]; then
        git -C "$1" rev-parse HEAD 2>/dev/null || echo unknown
    else
        echo unknown
    fi
}
# END kernel_stamp

rm -rf "${work:?}"
mkdir -p "$work"
echo "RUN-AGENT-EXEC start $(date -u +%Y-%m-%dT%H:%M:%SZ) source=$(git -C "$root" rev-parse HEAD) dirty=$([ -n "$(git -C "$root" status --porcelain)" ] && echo yes || echo no) niceness=$(nice) load=$load kernel=$(kernel_stamp "$kernel") candidate=$candidate baseline=$baseline"
python3 -I "$root/scripts/agent-exec.py" --self-test > "$work/self-test.log" 2>&1 ||
    { cat "$work/self-test.log"; echo "run-agent-exec: the driver's self-test failed" >&2; exit 1; }
tail -n 1 "$work/self-test.log"
python3 -I "$root/scripts/agent-job.py" --self-test > "$work/job-self-test.log" 2>&1 ||
    { cat "$work/job-self-test.log"; echo "run-agent-exec: the job runner's self-test failed" >&2; exit 1; }
tail -n 1 "$work/job-self-test.log"
if [ "${ABSD_AGENT_EXEC_SKIP_CASES:-0}" != 1 ]; then
rc=0
python3 -I "$root/scripts/agent-exec.py" --work "$work/run" --receipts "$work/receipts.jsonl" \
    --kernel "$kernel" --shell "$root/commands/absd-sh" --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" \
    --candidate "$candidate" --baseline "$baseline" > "$work/agent-exec.log" 2>&1 || rc=$?
grep '^AGENT ' "$work/agent-exec.log" || true
if [ "$rc" != 0 ] || ! grep -q '^AGENT EXEC OK ' "$work/agent-exec.log"; then
    tail -n 40 "$work/agent-exec.log" >&2
    echo "run-agent-exec: the run failed (receipts: $work/receipts.jsonl, serial logs: $work/run)" >&2
    exit 1
fi
echo "receipts: $work/receipts.jsonl"
fi
if [ -n "${ABSD_AGENT_JOBS:-}" ]; then
    set --
    for job in $ABSD_AGENT_JOBS; do
        test -f "$job" || { echo "run-agent-exec: no job file $job" >&2; exit 1; }
        set -- "$@" --job "$job"
    done
    rc=0
    python3 -I "$root/scripts/agent-job.py" "$@" --work "$work/jobs" --receipts "$work/job-receipts.jsonl" \
        --kernel "$kernel" --shell "$root/commands/absd-sh" --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" \
        --candidate "$candidate" > "$work/agent-job.log" 2>&1 || rc=$?
    grep '^AGENT ' "$work/agent-job.log" || true
    if [ "$rc" != 0 ] || grep -q '^AGENT JOB\( SET\)\? FAILED' "$work/agent-job.log"; then
        tail -n 40 "$work/agent-job.log" >&2
        echo "run-agent-exec: the job run failed (receipts: $work/job-receipts.jsonl, serial logs: $work/jobs)" >&2
        exit 1
    fi
    echo "job receipts: $work/job-receipts.jsonl"
fi
