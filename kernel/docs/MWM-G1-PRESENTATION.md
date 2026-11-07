# MWM G1 bounded presentation experiment

Status: **private `mwm-experiment` component source is integrated at `412d6eda`; whole-G1 runtime acceptance remains open**. The current observer correction is evidence-apparatus only. This is not supported ABI, a production compositor, or a claim that QEMU, physical hardware, timing, or client composition has been qualified. coordination record #128 owns the experiment. `KERNEL_ABI` and ordinary program routing do not change.

## Boundary and build selection

PID 1 opens a display, transfers writable/readable handles through the existing spawn-copy vector, and closes its own copy on both success and abort. The child runs with `SPAWN_NO_SPAWN`. Writable references are counted across duplicate, spawn, abort, close, and teardown. A read-only duplicate is an observer, not a writer. The final writable close masks the display, leaves normal console mirroring disabled, and permits a new open generation.

Only the experiment compiles `Object::Display`, these calls, or MWM routing. An ordinary build contains none of them. The `mwm-demo` command-line word selects init word `0x4d57`; optional `mwm-fault` requires the demo. Either option without the feature, fault without demo, or an incompatible SMP/operator composition is refused before init. The admitted execution target is one x86 QEMU GOP CPU, with the existing BSP serialization and interrupts disabled.

The fixture accepts only 1024×768, pitch 4096, 32-bit direct color, with red/green/blue shifts 16/8/0 and eight bits per channel. Other geometry returns `ERROR_IO` at open; this experiment does not claim arbitrary geometry support. No physical framebuffer address is returned or accepted from userspace.

## Private calls

| Call | Arguments | Result |
| --- | --- | --- |
| `0x7fd0 display_open` | `0, 0, 0` | New read/write display handle, or error |
| `0x7fd1 display_info` | handle, record pointer, `0` | `0` after a 48-byte record is copied, or error |
| `0x7fd2 display_present` | handle, request pointer, payload pointer | `0` after complete presentation, or error |
| `0x7fd3 display_mask` | handle, operation sequence, generation | `0` after complete mask, or error |
| `0x7fd4 display_console_restore` | handle, operation sequence, generation | `0` after restoring normal console mirroring, or error |
| `0x7fdf display_fault_fixture` | handle, generation, `0` | No normal return; triggers the existing unarmed kernel page fault |

Open requires PID 1, the pinned GOP geometry, zero current writers, and a non-exhausted next generation. A second open returns `ERROR_AGAIN`; non-PID-1 returns `ERROR_RIGHTS`; unavailable or unsupported geometry returns `ERROR_IO`. Failed handle insertion leaves generation, writer count, pixels, mirroring, and high-water unchanged.

`display_info` requires read right and a currently active handle generation. It takes no separate generation argument; the looked-up handle supplies that identity and the returned record reports it. Every mutation independently requires its handle, matching generation, and write right. Old generations return `ERROR_STALE`. Wrong or closed handles return `ERROR_BAD_HANDLE`; missing rights return `ERROR_RIGHTS`.

## Display information record: 48 bytes

All fields are explicit little-endian values, not native Rust structure layout. Reserved bytes are zero.

| Offset | Field |
| --- | --- |
| 0, 4, 8 | `width: u32`, `height: u32`, `pitch: u32` |
| 12, 13 | `bits_per_pixel: u8`, `kind: u8` (`kind = 1`, firmware direct color) |
| 14–15 | reserved |
| 16, 17 | red shift, red bits (`u8`) |
| 18, 19 | green shift, green bits (`u8`) |
| 20, 21 | blue shift, blue bits (`u8`) |
| 22–23 | reserved |
| 24 | `display_generation: u64` |
| 32 | `operation_high_water: u64` |
| 40 | `max_present_bytes: u64` (65,536) |

## Present request record: 48 bytes

| Offset | Field |
| --- | --- |
| 0 | `operation_sequence: u64` |
| 8, 12, 16, 20 | `x: u32`, `y: u32`, `width: u32`, `height: u32` |
| 24, 28 | `pitch: u32`, `format: u32` |
| 32 | `payload_length: u64` |
| 40 | `generation: u64` |

For this fixture, `format = 1 | (32 << 8)`. The operation sequence must be nonzero and exceed this open generation's high-water mark. Sequence or generation exhaustion refuses rather than wrapping: a mutation that cannot advance returns `ERROR_STALE`; an exhausted next open returns `ERROR_AGAIN`.

Presentation performs one transaction:

1. Copy all 48 request bytes once into a local snapshot and parse only that snapshot.
2. Check the display object, current generation, write right, and increasing operation sequence.
3. Validate the format and metadata with checked arithmetic: nonzero width, height, pitch, and payload length; `width * bytes_per_pixel <= pitch`; `x + width` and `y + height` within the framebuffer; `payload_length == pitch * height`; and payload length at most 65,536.
4. Validate the complete readable user payload range, then copy the complete payload into the fixed 64 KiB staging area.
5. Only after the complete copy succeeds, write the rectangle and advance high-water. Mask clears the existing background before advancing high-water. Console restore changes mirroring, not pixels, after its authority and sequence checks.

A bad snapshot, metadata, range, or later-page copy failure has no pixel, generation, high-water, or mirroring effect. A staging prefix is never presented. `ERROR_INVALID` covers malformed metadata, `ERROR_STALE` obsolete authority or sequence, and `ERROR_FAULT` an invalid snapshot or user-memory range/copy. Destination rows are checked against the mapped geometry before their spans are copied.

Normal console output is suppressed while presentation is owned. Last close and explicit mask use the existing background `0x102040`; neither implicitly restores normal mirroring. Console restore requires an active current-generation writer and an increasing sequence.

## Fault fixture and limits

The fault fixture requires the compile-time feature, `mwm-fault` boot gate, current-generation write authorization, valid GOP state, and no active drawing. It invokes the existing unarmed kernel page fault while the display is quiescent. Emergency output selection is independent of MWM progress and handles. This does not establish fatal rendering during MMIO/drawing reentry, UART-only fatal output, arbitrary timing, or physical-hardware behavior. Successful present and mask operations have no post-effect rollback claim; later UI must reconstruct content.

Host tests cover authority/refcount behavior, failed opens, stale handles and generations, explicit record encoding, metadata/range refusal, full-copy failure, mask/restore sequencing, fault gates, and incompatible boot selection. Their success is not QEMU or pixel evidence. The standalone MWM and independent offline oracle are implemented. The component source and ordinary integration reviews are accepted; corrected-apparatus review and integrated-product pixel evidence remain separate obligations.

## Build and offline verification

```sh
make mwm-protocol-test mwm-demo-iso mwm-fault-iso
python3 -I -m unittest discover -s scripts -p 'test_mwm_build.py' -v
python3 -I -m unittest discover -s scripts -p 'test_mwm_check.py' -v
```

The two ISO targets only build artifacts and SHA-256 receipts; they do not launch QEMU. The receipts cover `mwm.elf`, `init.elf`, the kernel ELF, and the selected ISO. The protocol suite covers exact `GO\n` parsing, fragmented input, split-pipeline/trailing-data refusal, bounded handoff and timeout, geometry records, independently formed rectangle bytes, and coordinator partial-spawn cleanup and ordering. The build-route suite proves that MWM and init differ and that ordinary init omits MWM routing.

Each capture precedes its literal `GO\n`, followed by a one-tick bounded quiet check. Any extra buffered byte during that handoff is an error, not input for the next phase. The host sends exactly one acknowledgement per capture and never pipelines acknowledgements. The sequence is a rectangle at `(16,16)`, a replacement rectangle at `(32,16)`, the last-close mask, then a different successor rectangle at `(32,32)`. The second-open refusal follows A's readiness and precedes its kill. The mask is captured before reopen, and ordinary console mirroring remains disabled until after the successor capture. The HMP greeting is consumed before the first screendump command. Every screendump targets a fresh sibling `.capture` file; an HMP `Error:` response or a missing new file fails observation, and only a successful capture atomically replaces the phase image. A failed later poll cannot silently reuse an older image.

A normal run additionally requires `MWM DEMO OK processes=1`, `USERSPACE BOOTSTRAP OK`, `EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0`, `EXTERNAL WORKLOAD OK`, and `ABSD BOOT OK`; a kernel-fault record is never normal evidence. After the `KERNEL FAULT vector=14` serial marker, the fault observer polls capture pairs at 0.2-second intervals with a 10-second deadline. Acceptance requires identical retained bytes, failure colors, and an independently font-checked `ABSD HALT code=2` notice on the second console row. An identical but incomplete pair is not evidence. Host/controller `.log` files belong outside the oracle root; its exact phase-file check is not relaxed. Offline validation of existing roots is:

```sh
python3 scripts/mwm-check.py --check-normal NORMAL_ROOT
python3 scripts/mwm-check.py --check FAULT_ROOT
```

The observation driver connects only to serial and HMP sockets supplied by a separately admitted execution envelope. It contains no QEMU launch path. On 2026-11-04, existing normal and fault images of component `b316a381` booted: all four presentation frames matched in each mode, normal reached `ABSD BOOT OK`, and fault red/white output with `HALT code=2` was observed. Both whole observers failed on extraneous log filenames, and the held fault capture pair differed because the first capture preceded the completed halt notice. Those failures remain historical. Offline replay verifies that the corrected halt check rejects the partial image and accepts the completed one, and that relocating host logs clears only the normal layout failure. These observations do not establish integrated-product runtime, timing, or qualification.

No direct or permanent client framebuffer mapping, generic shared memory or bulk IPC, raw-input mechanism, client composition, global successor election, serialized-export provenance, total retained-history guarantee, or #129–#132 implementation follows from this experiment.
