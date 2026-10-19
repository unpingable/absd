# hexdump: bounded Toybox adaptation, qualification pending

Toybox 0.8.15 pending hexdump, Copyright 2021 Moritz Röhrich, 0BSD
(see LICENSE). SOURCE.json identifies the exact archive/member, license,
source patch and resulting standalone C source. `scripts/stage-hexdump.py`
verifies these identities offline and stages only admitted regular members
into a fresh destination. It does not extract arbitrary archive paths.

Six mutually exclusive modes: default/-x little-endian two-byte hex, -b byte
octal, -c escaped character, -d two-byte decimal, -o two-byte octal, -C hex+ASCII.
-v expands repeated full blocks. -n limits bytes displayed; explicit zero
means none. -s consumes/skips bytes across the concatenation of input files.
No files means stdin; '-' uses stdin at its current stream position. Empty
files do not end a partial output line. Reported open/read/close/stdio errors return 2 (partial output may exist);
successful completion returns 0. External termination is separate: on Linux,
a closed output pipe normally terminates the process with SIGPIPE, not status2.
No status2 guarantee is made for signals or target-runtime termination. Options end at
first filename or '--'; conflicting modes fail. Custom -e/-f formats are
explicitly refused; this is not a general hexdump-format or POSIX guarantee.

Numbers: unsigned decimal (leading zero remains decimal, as upstream) or
0x hexadecimal; optional case-insensitive c/w/b/k/m/g/t/p/e suffixes mean
1/2/512/1024 powers respectively; d after k..e uses 1000 powers. Invalid,
negative and overflowing values refuse. The byte/offset domain is unsigned
64-bit; offset exhaustion fails rather than wrapping. No unbounded arithmetic
or memory claim: storage is a 4096-byte input buffer and two 16-byte lines;
time/output are proportional to consumed input. Skipping uses read/discard,
so supports stdin without a seek requirement and can be slow for huge skips.
Two-byte output order is explicitly little-endian on every host. Character
mode preserves upstream escape spellings and '??' for other nonprintable
bytes; canonical ASCII uses '.'. This is not locale-aware output.

Adaptation retains upstream formatter and full-line repetition algorithm;
replaces generated Toybox parsing/I/O with checked standalone plumbing.
Repairs unsigned-byte formatting, first-zero-line suppression, zero-limit
handling, remaining-skip arithmetic and final partial-buffer handling.
The finite-input independent Python oracle plus literal goldens cover these
claims. They do not establish target execution, cancellation, scheduling,
filesystem snapshot semantics or memory exhaustion behavior on ABSD.

Build explicit staged source through this directory's Makefile, SIDE=linux or
SIDE=absd with an identified kit compiler/POSIX archive. No change is made to
PORTS.tsv, default userland installation or operator image until actual target
build identities, demand closure, two-build reproducibility and steward guest
qualification are available. No placeholder digests are used.

Formalization consideration: stream concatenation, counters and repeat-state
claims use explicit bounded integer checks, golden vectors and independent
negative controls. No proof is claimed; a new general model/framework is not
needed for this small streaming utility. Controller owns acceptance; steward
retains integration and guest qualification authority.
