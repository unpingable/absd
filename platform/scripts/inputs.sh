# Sourced, not run: `. "$root/scripts/inputs.sh"` after `root` is set.
#
# Which qualification profile applies, where the external inputs are, and
# how a pinned input is checked and staged.
#
# ABSD_PROFILE is `core` or `full`. Core is ABSD alone: the kernel, this
# tree, crates.io. Full adds the extended integration programs, which run
# other projects' code on ABSD (Pulse, AG, Nightshift, NQ) and need those
# projects' sources at the pinned revisions. The default is `full` in a
# development checkout and `core` in a source release, which carries neither
# those sources nor the patches this tree applies to them: the full profile
# is run from the development repositories.
#
# Each location is, in order: its environment variable (ABSD_KERNEL_SOURCE,
# ABSD_PULSE_SOURCE, ABSD_AG_SOURCE, ABSD_NIGHTSHIFT_SOURCE, ABSD_NQ_SOURCE);
# for the kernel only, ../kernel beside this tree, its place in a source
# release; what absd-inputs.local.sh beside this tree, an untracked file a
# development machine may keep, assigns to that variable. That file is read
# as `NAME=path` lines, never run, and is not read at all in a source
# release. The resolved locations are exported under the same names, so the
# Python scripts (scripts/absd_inputs.py) and nested scripts see the same.
#
# An input is either a Git checkout (it has its own .git) or a plain
# directory, a snapshot. A checkout is read through its pinned commit; a
# snapshot has no commit, so it is checked by the Git tree identity of its
# files, which must be the pinned commit's tree. Either way what is staged
# is exactly what was hashed.

absd_given_kernel=${ABSD_KERNEL_SOURCE:-}
absd_given_pulse=${ABSD_PULSE_SOURCE:-}
absd_given_ag=${ABSD_AG_SOURCE:-}
absd_given_nightshift=${ABSD_NIGHTSHIFT_SOURCE:-}
absd_given_nq=${ABSD_NQ_SOURCE:-}
absd_release_manifest=$(dirname "$root")/SOURCE-MANIFEST.toml
ABSD_KERNEL_PROTECTED=${ABSD_KERNEL_PROTECTED:-}
if [ ! -f "$absd_release_manifest" ] && [ -f "$(dirname "$root")/absd-inputs.local.sh" ]; then
    while IFS='=' read -r absd_name absd_value; do
        case $absd_name in
        ABSD_KERNEL_SOURCE) ABSD_KERNEL_SOURCE=$absd_value ;;
        ABSD_PULSE_SOURCE) ABSD_PULSE_SOURCE=$absd_value ;;
        ABSD_AG_SOURCE) ABSD_AG_SOURCE=$absd_value ;;
        ABSD_NIGHTSHIFT_SOURCE) ABSD_NIGHTSHIFT_SOURCE=$absd_value ;;
        ABSD_NQ_SOURCE) ABSD_NQ_SOURCE=$absd_value ;;
        ABSD_KERNEL_PROTECTED) ABSD_KERNEL_PROTECTED=$absd_value ;;
        ABSD_REFERENCE_LINUX) ABSD_REFERENCE_LINUX=${ABSD_REFERENCE_LINUX:-$absd_value} ;;
        ''|'#'*) ;;
        *) printf '%s\n' "absd-inputs.local.sh: unknown line: $absd_name" >&2; return 1 2>/dev/null || exit 1 ;;
        esac
    done < "$(dirname "$root")/absd-inputs.local.sh"
fi
# The Linux reference programs fixtures/ag-native was produced with
# (scripts/make-reference-fixture.sh): prebuilt, pinned by digest in that
# fixture's manifest, and so not something a source release can carry.
ABSD_REFERENCE_LINUX=${ABSD_REFERENCE_LINUX:-$(dirname "$root")/absd-reference-linux}
if [ -n "${ABSD_PROFILE:-}" ]; then
    absd_profile_reason=${absd_profile_reason:-env}
elif [ -f "$absd_release_manifest" ]; then
    ABSD_PROFILE=core absd_profile_reason=source-release
else
    ABSD_PROFILE=full absd_profile_reason=default
fi
export absd_profile_reason
case $ABSD_PROFILE in
core|full) ;;
*) printf '%s\n' "ABSD_PROFILE must be core or full, not $ABSD_PROFILE" >&2; return 1 2>/dev/null || exit 1 ;;
esac
export ABSD_KERNEL_PROTECTED ABSD_REFERENCE_LINUX ABSD_PROFILE

# absd_input GIVEN DISTRIBUTED LOCAL: the first that applies, as a physical
# path when it exists; empty when none does.
absd_input() {
    if [ -n "$1" ]; then
        absd_found=$1
    elif [ -n "$2" ] && [ -d "$2" ]; then
        absd_found=$2
    else
        absd_found=$3
    fi
    if [ -d "$absd_found" ]; then
        (CDPATH= cd -- "$absd_found" && pwd -P)
    else
        printf '%s\n' "$absd_found"
    fi
}

ABSD_KERNEL_SOURCE=$(absd_input "$absd_given_kernel" "$root/../kernel" "${ABSD_KERNEL_SOURCE:-}")
ABSD_PULSE_SOURCE=$(absd_input "$absd_given_pulse" "" "${ABSD_PULSE_SOURCE:-}")
ABSD_AG_SOURCE=$(absd_input "$absd_given_ag" "" "${ABSD_AG_SOURCE:-}")
ABSD_NIGHTSHIFT_SOURCE=$(absd_input "$absd_given_nightshift" "" "${ABSD_NIGHTSHIFT_SOURCE:-}")
ABSD_NQ_SOURCE=$(absd_input "$absd_given_nq" "" "${ABSD_NQ_SOURCE:-}")
export ABSD_KERNEL_SOURCE ABSD_PULSE_SOURCE ABSD_AG_SOURCE ABSD_NIGHTSHIFT_SOURCE ABSD_NQ_SOURCE

# absd_source NAME (KERNEL, PULSE, AG, NIGHTSHIFT, NQ): the location, or a
# failure that names the variable. Only a script that needs an input asks.
absd_source() {
    eval "absd_found=\${ABSD_$1_SOURCE:-}"
    test -n "$absd_found" || {
        printf '%s\n' "ABSD_$1_SOURCE is not set: the $ABSD_PROFILE profile needs the $1 source directory" >&2
        return 1
    }
    printf '%s\n' "$absd_found"
}

# The scripts build in a disposable clone or copy of the kernel, never in
# the kernel source itself, in a linked worktree of it (whose .git is a
# file), or in a checkout ABSD_KERNEL_PROTECTED names (colon-separated).
absd_not_kernel_source() {
    test -d "$1" || return 0
    absd_found=$(CDPATH= cd -- "$1" && pwd -P)
    if [ -f "$1/.git" ] || [ "$absd_found" = "$ABSD_KERNEL_SOURCE" ]; then
        printf '%s\n' "refusing to build in a kernel source checkout: $1" >&2
        return 1
    fi
    case ":$ABSD_KERNEL_PROTECTED:" in
    *":$absd_found:"*) printf '%s\n' "refusing to build in a protected kernel checkout: $1" >&2; return 1 ;;
    esac
}

# A directory inside someone else's work tree (a snapshot in a cloned source
# release) is not a checkout: only its own .git makes it one.
absd_is_checkout() {
    test -e "$1/.git"
}

# absd_snapshot DIRECTORY [DESTINATION]: prints the Git tree identity of a
# plain directory's files, computed in a temporary repository with no user,
# system or attribute configuration; with DESTINATION (an existing empty
# directory) also writes there exactly the files that were hashed, as Git
# creates them, so permission bits a tree identity does not record (beyond
# executable or not) never reach a build. Refuses what the identity would
# not show at all: anything named .git, an empty directory, a special file.
absd_snapshot() (
    set -eu
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_NAMESPACE GIT_CEILING_DIRECTORIES
    odd=$(find "$1" \( -name .git -o -type d -empty -o ! \( -type f -o -type d -o -type l \) \) -print -quit)
    test -z "$odd" || { printf '%s\n' "not a clean snapshot: $odd" >&2; exit 1; }
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_ATTR_NOSYSTEM=1
    git init --quiet --bare "$scratch/git"
    export GIT_DIR="$scratch/git" GIT_INDEX_FILE="$scratch/index"
    set -- "$1" "${2:-}" -c core.autocrlf=false -c core.fileMode=true -c core.symlinks=true \
        -c core.attributesFile=/dev/null
    directory=$1 destination=$2
    shift 2
    git "$@" --work-tree="$directory" add -A -f .
    if [ -n "$destination" ]; then
        git "$@" --work-tree="$destination" checkout-index -a --prefix="$destination/"
    fi
    git write-tree
)

# The Git tree identity of a plain directory (see absd_snapshot).
absd_tree_id() {
    absd_snapshot "$1"
}

# absd_check_snapshot NAME DIRECTORY TREE: a snapshot's files are the pinned
# commit's tree.
absd_check_snapshot() {
    test -d "$2" || { printf '%s\n' "$1 source is absent: $2" >&2; return 1; }
    absd_found_tree=$(absd_snapshot "$2") || return 1
    test "$absd_found_tree" = "$3" || {
        printf '%s\n' "$1 snapshot $2 has tree $absd_found_tree, not the pinned $3" >&2
        return 1
    }
}

# absd_stage_input NAME SOURCE COMMIT TREE DESTINATION: the pinned tree into
# DESTINATION (an existing empty directory). From a checkout, COMMIT must
# have tree TREE and its files come out by `git archive`, so local edits
# there can never leak in; from a snapshot, the files are the snapshot's.
# Either way what lands in DESTINATION is hashed and must be TREE.
absd_stage_input() {
    if absd_is_checkout "$2"; then
        test "$(git -C "$2" rev-parse "$3^{tree}")" = "$4" || {
            printf '%s\n' "$1 commit $3 does not have the pinned tree $4" >&2
            return 1
        }
        git -C "$2" archive "$3" | tar -x -C "$5" || return 1
        absd_found_tree=$(absd_snapshot "$5") || return 1
    else
        absd_found_tree=$(absd_snapshot "$2" "$5") || return 1
    fi
    test "$absd_found_tree" = "$4" || {
        printf '%s\n' "$1 from $2 staged as tree $absd_found_tree, not the pinned $4" >&2
        return 1
    }
}

# absd_kernel_identity SOURCE: for a kernel snapshot, whether it is the tree
# the source release's manifest names; prints `manifest-verified`, or, only
# when ABSD_ALLOW_MODIFIED=1, `modified-allowed`. A snapshot with no manifest
# beside it, or one that differs, is refused: nothing else says which
# kernel this is.
absd_kernel_identity() {
    absd_manifest=$(dirname "$1")/SOURCE-MANIFEST.toml
    absd_want=
    if [ -f "$absd_manifest" ]; then
        absd_want=$(python3 -c 'import sys, tomllib
entries = tomllib.load(open(sys.argv[1], "rb")).get("component", [])
print(next((e[sys.argv[3]] for e in entries if e.get("path") == sys.argv[2]), ""))' \
            "$absd_manifest" "$(basename "$1")" tree) || return 1
    fi
    # In a clone of the release, Git knows the committed tree and whether
    # anything tracked changed; build outputs left in the directory are
    # ignored files and do not count. Without Git, the directory is hashed.
    if git -C "$1" rev-parse --show-toplevel >/dev/null 2>&1; then
        absd_found_tree=$(git -C "$1" rev-parse HEAD:./) || return 1
        test -z "$(git -C "$1" status --porcelain -- .)" || absd_found_tree=modified
    else
        absd_found_tree=$(absd_snapshot "$1") || absd_found_tree=unreadable
    fi
    if [ -n "$absd_want" ] && [ "$absd_found_tree" = "$absd_want" ]; then
        printf '%s\n' manifest-verified
    elif [ "${ABSD_ALLOW_MODIFIED:-0}" = 1 ]; then
        printf '%s\n' modified-allowed
    else
        printf '%s\n' "kernel snapshot $1 is ${absd_found_tree}, the source manifest names ${absd_want:-nothing}: set ABSD_ALLOW_MODIFIED=1 to test a modified tree" >&2
        return 1
    fi
}

# absd_kernel_run SOURCE COMMIT RUN: a disposable kernel tree at RUN (an
# existing empty directory): a clone at COMMIT, or a copy of a snapshot
# whose identity absd_kernel_identity has accepted. In a clone of a source
# release only committed files are copied.
absd_kernel_run() {
    if absd_is_checkout "$1"; then
        git clone --quiet --shared --no-checkout "$1" "$3"
        git -C "$3" checkout --quiet --detach "$2"
        test "$(git -C "$3" rev-parse HEAD)" = "$2"
    else
        test -f "$1/Makefile" || { printf '%s\n' "kernel source is absent: $1" >&2; return 1; }
        absd_identity=$(absd_kernel_identity "$1") || return 1
        if [ "$absd_identity" = manifest-verified ] && git -C "$1" rev-parse --show-toplevel >/dev/null 2>&1; then
            # From the top of the work tree: in a subdirectory `git archive`
            # would take that subdirectory's path within the tree it is given.
            git -C "$(git -C "$1" rev-parse --show-toplevel)" archive "$(git -C "$1" rev-parse HEAD:./)" |
                tar -x -C "$3"
        else
            cp -a "$1/." "$3/"
            rm -rf "$3/target" "$3/build"
        fi
        # What this copy is, for whatever records it (scripts/operator_image.py).
        if [ "$absd_identity" = manifest-verified ]; then
            python3 -c 'import sys, tomllib
entries = tomllib.load(open(sys.argv[1], "rb")).get("component", [])
print(next(e["commit"] for e in entries if e.get("path") == sys.argv[2]))' \
                "$(dirname "$1")/SOURCE-MANIFEST.toml" "$(basename "$1")" > "$3/.absd-identity" || return 1
        else
            printf '%s\n' modified > "$3/.absd-identity"
        fi
        test -f "$3/Makefile" || { printf '%s\n' "kernel copy at $3 is incomplete" >&2; return 1; }
        printf '%s\n' "ABSD KERNEL SNAPSHOT source=$1 identity=$absd_identity"
    fi
}

# absd_rust_remap: sets and exports ABSD_RUST_REMAP, a cargo --config value
# appending source-path remaps to the target's rustflags (.cargo/config.toml
# sets the rest), for every ABSD Rust build of this tree's programs
# (prepare-and-build.sh, build-ssh.sh, run-contain-matrix.sh). Rust keeps a
# source path as Cargo gives it: relative under the workspace being built,
# absolute elsewhere (the staged sysroot as ssh/ sees it, the Cargo
# registry). Those absolute paths are remapped so that the programs do not
# depend on where the tree is checked out (N3): the tree, in either
# spelling, to /absd, as the C kit does (scripts/build-c-kit.sh), and the
# registry's sources to /cargo/registry/src. Cargo's own -C metadata hashes
# a path dependency absolutely unless it sits inside the workspace, which is
# why ssh/ reaches the tree's crates through ssh/tree/ (ssh/Cargo.toml).
absd_rust_remap() {
    absd_remap=
    for absd_pair in "$root=/absd" "$(CDPATH= cd -- "$root" && pwd -P)=/absd" \
        "${CARGO_HOME:-$HOME/.cargo}/registry/src=/cargo/registry/src"; do
        case $absd_pair in
        *\'*) printf '%s\n' "absd_rust_remap: a path holds a quote: $absd_pair" >&2; return 1 ;;
        esac
        absd_remap="$absd_remap${absd_remap:+, }'--remap-path-prefix=$absd_pair'"
    done
    ABSD_RUST_REMAP="target.x86_64-unknown-absd.rustflags=[$absd_remap]"
    export ABSD_RUST_REMAP
}

# Complete target flags for the six full-profile builders. Encoded flags are
# mutually exclusive with Cargo's target/config arrays (which otherwise append).
# Keep absd_rust_remap's existing zero-argument callers unchanged. This only
# supplies flags; it does not establish Cargo metadata or artifact independence.
absd_full_rustflags() {
    ABSD_FULL_RUSTFLAGS=$(python3 - "$root" "${CARGO_HOME:-$HOME/.cargo}" "$@" <<'PY'
import os
from pathlib import Path
import sys

root, cargo, *arguments = sys.argv[1:]
if not 1 <= len(arguments) <= 2:
    sys.exit('absd_full_rustflags: expected family and optional Pulse cfg')
family = arguments[0]
cfg = arguments[1] if len(arguments) == 2 else ''
if family not in ('integration', 'nightshift', 'pulse', 'pulse-observe', 'nq', 'ag-loopctl'):
    sys.exit('absd_full_rustflags: unknown family')
if cfg not in ('', '--cfg pulse_absd_test_config') or (cfg and family not in ('pulse', 'pulse-observe')):
    sys.exit('absd_full_rustflags: unsupported family cfg')

def checked(path):
    # '=' is rustc's FROM=TO separator; control bytes include the encoded-flag
    # separator. Spaces and quotes remain single argument bytes, not shell/TOML.
    if not os.path.isabs(path) or '..' in path.split('/') or '=' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        sys.exit('absd_full_rustflags: unsupported or ambiguous path')
    return os.path.normpath(path)

root, cargo = checked(root), checked(cargo)
mappings = {}
def add(path, destination):
    for spelling in (checked(path), checked(os.path.realpath(path))):
        if spelling in mappings and mappings[spelling] != destination:
            sys.exit('absd_full_rustflags: one source spelling has conflicting identities')
        mappings[spelling] = destination

add(root, '/absd')
add(str(Path(cargo) / 'registry/src'), '/cargo/registry/src')
for stage in ('ag', 'pulse-source', 'nightshift', 'pulse', 'pulse-observe', 'nq', 'ag-loopctl'):
    add(str(Path(root).parent / ('absd-std-staged-' + stage)), '/absd-inputs/' + stage)
linker = 'user-linker.ld' if family == 'integration' else root + '/user-linker.ld'
flags = ['-C', 'link-arg=-T' + linker, '-C', 'link-arg=--gc-sections']
if family in ('pulse', 'pulse-observe'):
    flags += ['--check-cfg', 'cfg(pulse_absd_test_config)']
    if cfg:
        flags += ['--cfg', 'pulse_absd_test_config']
else:
    flags += ['--cfg', 'getrandom_backend="rdrand"']
# rustc uses the last matching prefix. More specific source paths go last;
# aliases for the same source are deduplicated rather than counted as coverage.
for source in sorted(mappings, key=lambda p: (len(p), p)):
    flags.append('--remap-path-prefix=' + source + '=' + mappings[source])
sys.stdout.write('\x1f'.join(flags))
PY
    ) || return $?
}
