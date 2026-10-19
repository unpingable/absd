# Bounded Toybox diff adaptation — host implementation, not installed

Source is Toybox 0.8.15 `toys/pending/diff.c` (pending/default-off upstream),
archive SHA256 `44e2bab43dfe2c171743297631ce558c6d9ed38b87a66fd751cef617574b375e`,
tag `a57b091d05ec366dcd4dd737784c03761cb6a4b1`. SOURCE.json pins archive,
selected source, license, reviewed patch and adapted bytes. The upstream
2014 author notices and release 0BSD LICENSE are preserved. This is an
adaptation of its line hashes, equivalence classes, candidate-chain LCS,
actual-byte match verification, and unified hunk construction. It is not a
new diff algorithm or the full Toybox multicall environment.

## Contract

`diff [-u] [--] file1 file2` compares two named regular files. Output is unified
with up to three context lines, always quoted pathname labels and no timestamps.
Exit 0 means captured bytes equal, 1 different, 2 operational error or refusal.
NUL anywhere in either input selects binary reporting, including beyond the
shorter input's EOF. Unsupported options, stdin `-`, directories, missing files
and nonregular inputs are errors. No input/metadata write, recursion, regex,
locale, whitespace folding, tempfiles or process spawning is implemented.

Inputs must remain stable through pathname lookup/open and capture. The wrapper
prechecks file type then checks the opened descriptor; concurrent replacement
with a FIFO between these operations is outside the stable-input contract.
Each file is captured once into a bounded buffer. Hashing, verification and
rendering use that same captured sequence, so later pathname/content changes
cannot change rendering. Capture is **not** an atomic snapshot of concurrent
writes; it reports the bounded sequence read. Neither stat sizes nor zero ABSD
timestamps establish mutation detection or a shared two-file instant.

Limits are 65,536 captured bytes and 1,024 lines per input (a nonempty final
fragment counts as a line), 65,536 candidate allocations, 1,000,000 candidate
search/equivalence traversal steps, and 4 MiB cumulative dynamic allocation
requests, including reallocation requests and captures. libc-internal buffering
and stack are additional; no target fit claim is made without ELF/demand and
target measurement. Allocation/work refusal can occur within byte/line limits.
The capture reads one extra byte to distinguish the exact byte limit from
excess; at most 65,537 bytes are read from each file, once. No repeated physical
read passes. Hash arithmetic is uint32_t modulo arithmetic with low31 bits used.

Read, initial seek, input close, allocation and stdio-reported output failures
return 2. External signal termination is separate: on a Linux host a closed
pipe can terminate the process with SIGPIPE before stdio reports an error.
This adapter adds no signal emulation to ABSD; signal termination does not
establish equal/different or the normal status2 path.
Comparison output may be partial on error; callers must inspect status. Error
status has precedence over equal/different; no partial output establishes a
valid difference. Error exit can leave process-local allocations for process
teardown; there is no daemon or persistent library entry point.

## Reproduce and qualification boundary

From a clean source checkout, with the exact retained/downloaded archive:

```
python3 scripts/stage-diff.py /path/to/toybox-0.8.15.tar.gz /new/empty-parent/staged
make -f userland/diff/Makefile ROOT="$PWD" SRC=/new/empty-parent/staged OUT=/new/host-output SIDE=linux
python3 userland/diff/test.py --out /new/test-output
```

Staging refuses a changed archive, patch or source identity and an existing
destination. It extracts only diff.c and LICENSE as bytes, no archive paths or
symlinks. It applies the explicit patch with zero fuzz and verifies its output.
The standalone source-specific Makefile accepts SIDE=absd with explicit CC_ABSD
and POSIX_A; this does **not** identify or qualify a current mutable C kit.

No `PORTS.tsv` row, installed `/bin/diff`, operator-image inclusion, accepted
binary hash, guest case or manual claim is added by this host-only lane.
Target completion still requires exact kit/toolchain/source identities, demand
and ELF gate, two clean deterministic builds, and independent review before
adding real gated/stripped hashes to PORTS.tsv. Then extend the existing
install/provenance/manual/matrix route and obtain steward guest qualification.
The accepted existing ports and digests are untouched. A Linux host reference
or Makefile target is not target execution evidence.

## Formalization consideration

Proposition: normal completion partitions equal/different captured bytes, while
any observed operational failure or limit refusal yields 2. Preconditions are
the stable-input lookup contract and ordinary libc behavior; concurrent atomic
snapshot and arbitrary LCS optimality are excluded. Explicit bounded counters,
unsigned arithmetic, semantic hunk replay, deterministic error/limit controls
and independent review are proportionate here; no additional proof framework
is introduced. Reviewer owns source/host claim acceptance; steward retains
integration/guest acceptance. No kernel ABI or replacement-state change occurs.
