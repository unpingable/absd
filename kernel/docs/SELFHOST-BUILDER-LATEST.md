# Isolated latest-based self-hosting builder

The branch lane/selfhost-latest-20261029 starts at kernel
ba67c7e4f9e61eabd82af9f8235acda3b8ea1a7c and the paired platform starts at
d50390c24dc5ace769604b4fdc25034352974f3f. These are the owner-designated
rolling latest inputs recorded in #24 and latest-integration-20261029.
The original self-hosting branches and receipts remain unchanged.

## Selecting the builder profile

Every value this document describes is selected only by the kernel feature
`builder-profile` (coordination record #115 rework, owner decision 2026-11-01). The
experimental `builder-large-envelope` implies it. Without the feature a build
has latest's defaults exactly, and the history below describes the profile,
not the default.

| Value | Default | `builder-profile` | `builder-large-envelope` |
|---|---|---|---|
| `USER_HEAP_PAGES` | 8,192 (32 MiB) | 98,304 (384 MiB) | 524,288 (2 GiB, from GiB 1) |
| `KERNEL_STACK_PAGES` | 8 | 16 | 16 |
| `MAX_LEAF_TABLES` | 32 | 224 (30 + 2 + 192 from the windows) | 1,056 |
| `MAX_FRAME_ADMISSION_FRAMES` | 65,536 | 131,072 | 131,072 |
| init `EXTERNAL_WAIT_TICKS` | 120,000 | 7,200,000 | 28,800,000 |
| Self-host fault diagnostics | off | on | on |

The VM free-run search, the heap hint and the reservation-prefix arithmetic
(`SERVICE_HEAP_PAGES`, `heap_search_end`) are on the default path; by default
the prefix is the whole window, so they do not change what a process may map.
`abi/frame-admission-v0.toml` keeps the default 65,536, the pairing value.
The kernel refuses an ABI-only selection of either feature at compile time:
embedded programs and build.rs budgets follow the kernel feature
(`scripts/build-user.sh` forwards both).

Accounting under the profile is derived from the geometry, not fixed numbers:

- Served init commits `SERVED_INIT_FRAMES = MAX_LEAF_TABLES x 512 +
  MAX_LEAF_TABLES + 2 + USER_DIRECTORIES + KERNEL_STACK_PAGES`
  (`src/frame_geometry.rs`), 16,427 by default and 114,931 under the profile.
  build.rs passes it to init as `ABSD_SERVED_INIT_FRAMES`.
- Each served image's budget is `service_frames` of the exact linked ELF: the
  retained vectors are 9,333/9,434 by default, 99,629/99,730 under the profile.
  A served profile build therefore commits about 314k frames (about 1.2 GiB)
  and is not admitted at 256 MiB; 256 MiB served admission is a property of
  the default build only.
- The SMP pressure actor (`ACTOR_FRAMES`) is 16 image + 3 upper + 3 leaf +
  2 user-stack + `KERNEL_STACK_PAGES` + 1 scratch: 33 by default, 41 under the
  profile.

The builder envelope still refuses `frame-admission-v0` at compile time.

The initial code commit 0a3e9e1 ported the private builder profile from
4be194b37e027da14b4ee03153d96c73459f16ce: 288 MiB anonymous heap window,
224 leaf-table slots, numeric admission ceiling 131,072 frames, and a finite
25-minute external-workload deadline. The 32 KiB kernel stack was already
present on latest. Frames still require real backing and remain allocated
on demand. The enlarged numeric range does not create backing capacity.
The 32 MiB executable-file limit, 60 MiB executable window and 1 GiB user
region are unchanged. These branch-local settings are an experimental
builder profile, not a supported ABI or resource-contract promotion.

The ordinary stack-growth total and audit predicates from latest are
unchanged. Per-exit memory diagnostics and rejected fault-address logging
were not ported. The host geometry and refusal tests reflect only this
private profile. Original native execution and size/peak receipts continue
to apply to their original sources. The later bounded runs below identify
the latest-based composition separately.

Verification so far: cargo test --workspace --exclude absd-user --features
frame-admission-v0 --locked and cargo fmt --all -- --check, with installed
Rust 1.98.0, offline, nice 19, CPUs 0 and 1, two build jobs. Native09 and
Native10 then compiled, linked and ran the std file workload and its global
assembly variant on runner kernel 0a3e9e1 with platform launcher/FSD96dd7525.
Native11 built all 13 platform/runtime library commands, and Native13 compiled,
linked and ran a consumer using those actual libraries. Canonical bounded
finalization, immutable-input checks and zero ownership/block errors passed.
The later receipts have independent technical review. They prove bounded
builder workloads, not an ordinary-suite acceptance or complete U6. Bootstrap
std, compiler, tools, host-built runner and GRUB remain declared seeds. RC2,
latest/main refs and accepted source were not changed.

Evidence: archived-occurrence
Native evidence: latest-sdk-products-11, latest-sdk-consumer-products-13,
claude-native-platform-review-01 and codex-runtime-buildscript-review-04 in
the same Native05 directory. The new runner has no per-exit peak telemetry;
no new compiler heap peak is claimed from these runs.

## Full current kernel build profile

The current branch advances that experimental configuration to a 384 MiB
heap and a finite 120-minute external-workload deadline, within the existing
125-minute host-runner limit. The 224 leaf slots and 131,072-frame numeric
admission ceiling remain sufficient: the maximum 60 MiB image, 384 MiB heap
and 4 MiB stack occupy 30 + 192 + 2 leaves. All mappings still require real
backing. The supported resource contract and ordinary stack-growth acceptance
predicates remain unchanged.

The reason is a concrete larger workload. The exact current 56-command
kernel/userland recipe was captured from source 0a3e9e1 and replayed with the
synchronous Rust 1.95 Cranelift compiler and direct LLD on the host. Its final
kernel allocation peak was about 305 MiB, above the previous 288 MiB ceiling.
This is a host allocation observation, not a new native heap measurement or
proof that 384 MiB suffices. Earlier full native builds also took about
102 minutes, so the 25-minute library-workload deadline cannot bound their
replay. Both previous configurations and their receipts remain preserved.

The new profile must be identified separately in native build and boot
receipts. Bootstrap core/std, compiler, tools, host-built kernel/helpers and
GRUB retain their own provenance. A host build or a successful library batch
does not establish a full native successor build.

## Bounded 64 KiB kernel-stack experiment

Native23 reproduced an init memcpy fault before image assembly. Its saved
server pointer and nearby saved registers contained the same alternating
zero/all-ones words as AddressSpace::EMPTY. The compiled spawn-many call
chain has at least 38,400 bytes of fixed frames before call/trap overhead,
which exceeds the existing 32 KiB kernel stack. The exact final-only MIR4
control did not reduce these frames. This is evidence for a stack-overflow
hypothesis; a successful larger-stack guest is still required.

This branch tests sixteen kernel-stack pages (64 KiB) through the single
BUILDER_KERNEL_STACK_PAGES constant shared by allocation, reclamation, and
frame geometry. The ABI default remains eight pages. Construction and
service budgets charge eight additional physical frames for every process;
the geometry test vectors change by exactly eight for that allocation.
The ordinary user stack-growth and audit acceptance predicates are unchanged.
The supported resource contract, accepted source and RC2 remain unchanged.
A 64 KiB experiment does not prove a minimum stack or a bound on every path.

Both the builder kernel library and final executable must be recompiled:
the library owns frame geometry and the executable owns stack allocation.
The previous 54 user/ABI outputs remain declared inputs. Native compilation,
image assembly, successor boot and ordinary-suite acceptance must be reported
separately for this new profile. Live replacement or rollback is not claimed;
this remains a disposable cold-boot experiment with no state transfer.

The supported ACPI script still requires a 32 KiB kernel-stack capacity;
this private 64 KiB run cannot qualify that contract. The script is unchanged.
Served-mode admission is also outside this experiment: its init reservation
and build-script service budgets must be re-derived before using this profile
in served mode. Current native builder occurrences use the nonserved durable
FSD route and identify their exact default kernel configuration.

## Map free-run search (#115)

Commits f358494..5704ced (ported from research/large-process-20261030
8c21d4f..be76ce5). The VM keeps page directories on demand and reads leaf
tables from directory entries instead of a 224-slot side table, which also
drops `AddressSpace` from about 3.6 KiB to 40 bytes (56 with the envelope). Each leaf table's
present-entry count is kept in bits 52-61 of the directory entry that
references it, bits the processor ignores there; a compile-time check proves
they miss the address, flags and XD, and an entry with PS set is refused
where the count is read or written (user directories never map 2 MiB pages).
`find_unmapped_run` reads each leaf's directory entry once, skips a leaf with
fewer free pages than the run still needs (carrying only its trailing free
pages) and reads other leaves in order; it returns the same lowest run as the
page-by-page search. Unaligned bounds or a zero count yield no run in every
build, as are bounds outside the user region. The `builder-large-envelope`
feature (3 GiB region, 2 GiB heap window, eight-hour workload deadline) is
opt-in and refused with frame admission; scripts/build-user.sh passes it to
the embedded programs so a cargo build agrees with the kernel's layout.

Required gates for this code, in addition to the cargo test and fmt gates
above (`cargo test` does not compile src/vm.rs):

    cargo run --release --example large_envelope_vm
    cargo run --release --example large_envelope_vm --features vm-read-count
    cargo run --release --example large_envelope_vm --features builder-large-envelope,vm-read-count

Measured on the native core compile in a 3 GiB guest with native rustc
a5a202af: SYS_MAP was 1,780 s of 1,939 s (272,697 calls at 6.5 ms); after the
change core takes 80 s and the compiler_builtins/alloc batch 46 s, with
byte-identical outputs. Host fixture: examples/large_envelope_vm.rs (run it in
both layouts and with `vm-read-count`; `cargo test` does not compile vm.rs).
Evidence and reviews: archived-runs/selfhost-20261027/toolchain-closure-01/perf-01.

## Frame admission with the builder envelope (#115)

Commits dc1d692..9e7f16e. A served service's frame budget
(`frame_geometry::service_frames`, used by build.rs for fsd and sshd under
frame-admission-v0) charged the whole heap window; with the 2 GiB envelope
that is about 526k frames per service, over the 131,072-frame admission cap.
It now charges `SERVICE_HEAP_PAGES`: the whole window without the envelope
(nothing changes there), 98,304 pages (384 MiB) with it. `map` for a process
holding a reservation searches only that prefix
(`frame_geometry::heap_search_end`), so its heap cannot spend frames promised
to its stack; only unreserved processes get the 2 GiB window, and a reserved
process keeps a 384 MiB heap whatever its total. The compile-time guard is
narrowed to frame-admission-v0: frame-admission-core builds with the envelope,
and so do the private frame-reservation-experiment and
frame-admission-qualification builds (not normal builds: their 0x7ff0
self-admission has no authority check). Served admission with the envelope is
still refused in every normal build, and the ABI's envelope feature cannot be
selected without the kernel's. A reservation larger than image, stack window,
384 MiB heap and page tables leaves the remainder idle (unusable by the process
and by others) until the process exits.

Evidence (archived-runs/selfhost-20261027/toolchain-closure-01/perf-01 and served-01):
examples/large_envelope_admission.rs (real vm.rs and FrameAllocator, both
layouts: reservation caps data and page-table frames, unreserved processes
cannot take reserved capacity, unbacked promises are refused, teardown restores
the pool, the real service_frames budget fills its heap prefix and still grows
the whole stack); a reserved guest whose stack grows after heap exhaustion
(the bound-removed mutant faults); and one served-matrix link-down boot with
frame-admission-v0 and the envelope on a scratch kernel with the guard lifted
(7/7 checks, accounting records=0 status=ok). The reserved search bound in
syscall_map is exercised only by guest boots; the host fixture mirrors it.

Required gates, with the map-search ones above:

    cargo run --release --example large_envelope_admission --features frame-admission-core
    cargo run --release --example large_envelope_admission --features frame-admission-core,builder-large-envelope
