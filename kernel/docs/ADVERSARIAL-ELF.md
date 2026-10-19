# Adversarial ELF / `spawn_image` qualification

Bounded spike, 2026-10-02, from kernel `main` 4212fff. The question: can
caller-controlled image bytes make the loader overflow arithmetic, create
inconsistent mappings, violate segment permissions, accept an invalid entry
point, leak partially built state, or leave resources or accounting wrong
after a refusal?

Result: **no kernel defect found.** Every malformed image in the matrix is
refused with a defined error, no refusal leaves a process, handle, frame,
pipe, cell, or PID behind, an unrelated process is untouched, and a valid
image starts immediately after every case. Disposition: *adversarial ELF
parsing qualified for the current loader implementation.* This is not a
claim about ELF parsing in general.

## Loader as implemented

Read from source (`src/elf.rs`, `src/sched.rs` `spawn_from`/`load_process`/
`populate`/`release_resources`, `src/syscalls.rs` `syscall_spawn_image`,
`src/vm.rs` `map_user_page`):

- **Request.** `image_bytes` must be 1..=`MAX_SPAWN_IMAGE_BYTES` (32 MiB),
  else `-22`; the whole range must be mapped user memory (`check_user_range`),
  else `-14`. Both are checked before a slot is claimed. Every ELF refusal is
  `-8` (`ERROR_NOT_EXECUTABLE`); frame exhaustion during load is `-12`.
- **Header.** At least 64 bytes; magic, `EI_CLASS`=2, `EI_DATA`=1,
  `e_type`=`ET_EXEC`, `e_machine`=62, `e_version`=1. `EI_VERSION`,
  `EI_OSABI`, `e_ehsize`, `e_flags`, and the section-header fields are never
  read. `e_phentsize` must be 56, `e_phnum` nonzero (`PN_XNUM` has no
  meaning), and `e_phoff + 56 * e_phnum` must not overflow or pass the image
  end. The multiplication cannot overflow (`u16 * 56`).
- **Program headers.** Read one at a time into a kernel copy. `PT_NULL` is
  skipped; any type other than `PT_LOAD` is refused (including
  `PT_GNU_STACK` and `PT_INTERP`); at most 8 loads. Each load needs
  `memsz > 0`, `filesz <= memsz`, `offset + filesz <= image length` (checked),
  `vaddr + memsz` without overflow (checked), a nonzero power-of-two
  alignment with `vaddr ≡ offset (mod align)`, and no flag bits beyond R/W/X.
- **Entry.** Must lie in `[vaddr, vaddr + memsz)` of a segment with `PF_X`.
  It may lie in that segment's zero-filled tail.
- **Placement (loader).** Each segment must lie inside
  `[USER_IMAGE_MIN, USER_IMAGE_MAX]` (the end may equal the maximum). This
  check comes before page rounding and is the only guard against rounding
  overflow (the mutant below shows what happens without it). Pages are mapped
  one at a time, and any page already mapped fails the spawn. Two segments
  therefore may not share a 4 KiB page, even when their byte ranges are
  disjoint, which is stricter than Linux.
- **Contents.** Frames are zeroed when mapped; exactly `filesz` bytes are
  copied, page by page, through the child's translation. BSS is the zeroed
  remainder. The parsed program-header copy is what the loader uses, so the
  caller rewriting its image during the call cannot change validated fields.
- **Permissions.** `PF_W` sets the writable bit, and its absence leaves
  pages read-only. Without `PF_X` the page is NX. `PF_R` is not
  representable on x86, so a present page is always readable. **There is no
  W^X rule**: an R+W+X segment is mapped writable and executable. No ABSD
  document claims W^X for the loader (`DESIGN-INFLUENCES.md` lists it as a
  future default).
- **Rollback.** Any load failure runs `release_resources` (address space,
  kernel stack, with a panic if the PID still owns a frame) and `unclaim`
  (slot back to `Empty`, PID rewound when it was the newest). A refused
  spawn never reaches `activate_spawn`, so it is never runnable and never
  printed as `SPAWN OK`.

Existing coverage before this spike: `scripts/spawn-image-test.sh`
(`image_probe`: one positive image; malformed magic, truncation, entry,
below/above window, `PT_INTERP`; request-level refusals) and three parser
unit tests in `src/elf.rs`.

## The matrix

`user/src/bin/elf_matrix.rs`, run by `make elf-matrix-test`
(`scripts/elf-matrix-test.sh`, expected output `scripts/elf-matrix.expected`).
Every image is built byte by byte from one template: R+X code at
`USER_IMAGE_MIN` from file offset 0x1000, and R+W data at +0x10000 from
0x2000 with 16 file bytes, two pages of memory, and 0xaa garbage after
`filesz` in the file. The template code checks its own data word, that
the bytes past `filesz` are zero on the same page and on the next one, and
exits 42.

Per case the probe:

1. takes `resource_census` (processes, handles, pipes, cells, frames);
2. calls `spawn_image`; a started child is reaped and its outcome recorded,
   and its PID must be exactly the previous PID plus one;
3. requires the census to be identical;
4. starts a known-good control image, which must exit 42 with the next PID
   and leave the census identical again.

A sentinel child spawned before the matrix, which has exited but is not
reaped, must still report `Exited(42)` at the end. The script also requires
the exact number of `SPAWN OK ... program=image` lines (115: 27 accepted
cases + 87 controls + the sentinel), the kernel's final
`EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0`, and no panic or
kernel fault.

| Group | Cases (result) |
|---|---|
| Header / truncation | `len-1`, `len-63`, `len-64`, `ph-truncated`, `magic`, `class-32`, `class-3`, `endian-big`, `type-dyn`, `type-rel`, `machine-386`, `version-0`, `version-2`, `phentsize-{0,55,57,ffff}`, `phnum-{0,ffff}`, `phoff-overflow`, `phoff-at-end`, `phoff-straddles-end` (all -8); `ident-version-0`, `osabi-255`, `ehsize-ffff`, `phoff-unaligned` (accepted: fields unread / bytewise reads) |
| Arithmetic / bounds | `offset-overflow`, `offset-beyond-image`, `filesz-beyond-image`, `filesz-gt-memsz`, `vaddr-overflow`, `memsz-huge` (2^63), `memsz-0`, `vaddr-noncanonical`, `vaddr-kernel-half`, `end-at-u64-max` (vaddr+memsz = 2^64-1, no add overflow; refused by the window before rounding), `window-past-end`, `window-below-start` (all -8); `filesz-at-image-end`, `window-last-page` (accepted); `image-exactly-max` (32 MiB, segment bytes are the last 16 of the image: accepted), `image-max-plus-1` (-22) |
| Segment relationships | `overlap-bytes`, `same-start-conflicting` (R+W vs R+X), `same-start-identical`, `disjoint-bytes-shared-page`, `overlap-code`, `memsz-0-extra`, `loads-9`, `gnu-stack`, `flags-unknown-bit` (all -8); `filesz-0-bss-only`, `adjacent-pages`, `descending-order`, `loads-8`, `loads-8-with-null` (accepted) |
| Alignment | `align-0`, `align-3`, `align-2m-incongruent`, `align-2-63`, `vaddr-offset-incongruent` (all -8); `align-1`, `straddle-page-copy` (4 file bytes straddling a page in file and memory; the dword reads back intact) (accepted) |
| Permissions | `perm-rx-write`, `perm-rw-exec`, `perm-r-write`, `perm-r-exec`, `perm-none-write` (child #PF, vector 14; error codes 0x7 write and 0x15 instruction fetch); `perm-r-read`, `perm-none-read`, `perm-x-read` (readable: x86), `perm-rwx-write`, `perm-rwx-write-exec` (store code, then run it: permitted) |
| Entry | `entry-in-rw`, `entry-unmapped`, `entry-at-segment-end`, `entry-zero`, `entry-noncanonical`, `entry-kernel`, `x-segment-noncanonical`, `x-segment-kernel`, `x-segment-identity-map` (all -8); `entry-in-x-bss`, `entry-last-byte` (accepted, child #PF; contained) |
| Partial failure | `late-overlap`, `late-past-window`: seven segments (code, data, five 16-page segments) map before the eighth, which the parser accepted, fails in `populate`. Both -8, census identical, control spawns next PID |

Host unit tests (`src/elf.rs`: `adversarial_matrix_refusals_name_their_check`,
`placement_is_left_to_the_loader`) pin the specific `ElfError` for 24
refusals. The syscall reports all of them as -8, so these tests show each
image fails the check it targets, not a later incidental one. They also pin
which cases the parser deliberately leaves to the loader.

## The harness is not vacuous

Each mutant was applied to the kernel temporarily, run through the matrix,
and reverted:

| Mutant | Detected as |
|---|---|
| `unclaim` does not rewind the PID | `FAILED at pid not contiguous` after the first refusal |
| `populate` copies up to `memsz` (bytes past `filesz` reach BSS) | 13 accepted cases exit 2 (`MISMATCH`), BSS-zero check |
| `populate` window check removed | `memsz-huge` -12 instead of -8, then kernel panic on the page-rounding add (`end + PAGE_SIZE - 1`) |

## Defects

- Kernel: none.
- Harness, found while building: the probe first used the default workload
  because `elf_matrix` was not in `scripts/build-user.sh`'s program list.
  `map` takes at most 64 pages per call, so the 32 MiB image is mapped in
  128 contiguous chunks.

## Observations (policy, not defects)

- No W^X: writable+executable segments are honored. If W^X becomes policy,
  `perm-rwx-*` are the cases to flip.
- `PF_R` is not enforced; flags 0 and X-only segments are readable.
- An entry in the zero-filled tail of an executable segment is accepted; the
  child faults on its first instruction and is contained.
- Header fields the parser never reads (`EI_VERSION`, `EI_OSABI`,
  `e_ehsize`) are accepted with any value.
- Page rounding is protected only by the window check, which comes first. A
  `checked_add` there would be defence in depth; it is unreachable today.

## Partial allocation rollback follow-on (source added 2026-10-11)

`user/src/bin/image_rollback.rs` and `make spawn-image-rollback-test` add a
separate local VM qualification for the actual `spawn_image` syscall. The
`spawn-image-rollback-test` kernel feature alone interprets syscall 31's
normally reserved third word as a one-call frame allowance: a nonzero value
`N` allows at most `N` new frames (zero leaves the normal unlimited syscall).
The ordinary kernel still requires this word to be zero. The quota is
installed after request and transfer validation, covers the complete
`spawn_image` construction, and is
removed before syscall publication or refusal returns. The kernel lock
serializes this bounded quota with other frame allocation.

The valid three-segment image spans three separate 2 MiB page-table regions.
Its construction needs three address-space frames, three image page tables,
three image frames, one stack page table, two user stack frames, and eight
contiguous kernel stack frames (20 total). A 20-frame bounded positive control
exits 42 and seeds PID continuity. Allowances 1 through 11 then refuse at
distinct single-frame allocation depths, including page-table and
user-frame allocation; 12 through 19 refuse the final contiguous stack. For
each refusal the probe requires `-12`, byte-identical
`resource_census` and `frame_stats` before and after, an unchanged live cell
whose handle was offered for copying, and a valid `spawn_image` immediately
afterward that exits 42, consumes the next PID and reclaims to the same
census. The host script requires exactly 20 image-child publication lines
and final global resource counts of zero.

**Qualification status:** source and host/static checks only on this lane;
the guest result remains unqualified until U1 terminal/resource admission.
The exact future command from this source revision is:

```sh
make spawn-image-rollback-test QEMU=qemu-system-x86_64
```

This command builds a feature-specific external kernel and user probe and
runs the local VM. Its receipt must identify the qualified source revision,
QEMU identity, serial log, exit status, exact output match and final resource
line. No guest outcome is inferred from host checks.

Formalization consideration, decision owner: kernel lane implementer,
2026-10-11. Source input `d55fbec89ab9607bad0f10a061ac5f677eeb4727`;
the result identity is the commit containing this section. Proposition: for
each admitted allowance 1..19, a failed child construction restores the
parent-visible resource census and does not publish the child; the next
unlimited spawn succeeds. Scope: the single-CPU external local VM and one
synthetic ELF with three distinct image page tables. Counterexamples not
covered: concurrent image mutation, failures after handle insertion, and
hardware transfer. Practical tests and the existing ownership-tag assertions
are sufficient for this bounded regression case; a small transition model
would be useful if the loader's construction order or publication boundary
changes. This decision does not claim guest qualification before the run.

## Not proven

- The original ELF matrix did not drive frame exhaustion through
  `spawn_image`; the separate follow-on above is pending guest qualification.
- An image source becoming unreadable mid-load (`ElfError::Unreadable`)
  cannot be produced by a single-threaded caller, since the whole range is
  checked before the slot is claimed; it is untested.
- Concurrency: the matrix runs on the boot CPU only; no other CPU mutates
  the parent's image during the call.
- The matrix is deterministic and compact, not fuzzing. The parser was not
  exhaustively explored beyond these 87 images and 24 unit cases.
- QEMU/TCG only.
