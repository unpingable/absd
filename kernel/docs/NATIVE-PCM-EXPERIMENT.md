# Native PCM experiment (#96)

Opt-in only. A default kernel build has no VirtIO Sound driver, playback object
or private PCM call, and ignores the `pcm-*` command-line words. Its embedded
init has neither the PCM startup modes nor the playback grant: `build.rs`
passes `ABSD_USER_NATIVE_PCM=1` to `scripts/build-user.sh`, selecting the
userspace `native-pcm-experiment` feature, only when the kernel feature is on,
so on a default build init arguments 0x50434d..0x504351 are unknown startup
modes. A nonempty `ABSD_PCM_PLAYBACK` without the kernel feature fails the
build; unset or empty selects no grant. Staged disks
for the SSH experiment also need the `/var/recovery.guard` and
`/var/recovery.resume` files that fsd requires for writable entry.

Build `sh scripts/audio-build.sh pcm-tone` from the kernel root. The image
runs an ordinary native init process which produces two seconds of S16 stereo
48kHz PCM: 480Hz left and 800Hz right, triangle waves with peak magnitude8000.
`pcm-probe` instead initializes and stops the device without producing samples.
Neither command runs QEMU. Guest execution needs an independent admitted host.

The driver feature is `native-pcm-experiment`; default builds add no playback object or
private syscall. There is no supported ABI promotion. The guest must have modern
VirtIO Sound PCI (1af4:1059), e.g. `-device virtio-sound-pci,audiodev=pcm` and
`-audiodev wav,id=pcm,path=output.wav,out.frequency=48000,out.channels=2,out.format=s16`.
Use the canonical experiment runner once available; do not launch on build_host's
occupied qualification slot. QEMU's WAV output is device evidence, not live
hearing on client_host. No capture-side stream is exposed to applications.

Private calls use the normal three-argument syscall entry:

| Number | Arguments | Result |
| --- | --- | --- |
| 0x7fe0 | zero, zero, zero | Init-only root playback handle, one per boot |
| 0x7fe1 | handle, PCM address, byte count | Accepted bytes; AGAIN if full |
| 0x7fe2 | handle, status address, 48 | Six little-endian u64 words below |
| 0x7fe3 | handle, zero, zero | Latch submission off, then stop/release/reset after queue drains; AGAIN if pending |

Status words: version1; rate48000 with channels2 at bit32 and samplebits16 at bit40;
submitted frames; completed frames; pending buffers; latency bytes in low32bits,
running at bit32 and failed at bit33. Device failure is returned as IO rather than
successful status. Read rights permit status; write rights permit submit/stop.
Only init can open, and only after the explicitly requested PCM boot initialized
the device. Existing spawn/transfer/duplicate paths delegate handles and rights.
No userspace address reaches DMA. Releasing the last writer handle cancels
playback; that is not a successful drain. A dead producer's handles are
released when the kernel reaps it, not at the instant it dies. Opening again requires a fresh boot in this slice.

Submissions accept at most1920bytes (480frames/10ms), a whole number of stereo
frames. Five buffers bound kernel PCM payload storage to9600bytes. Ordinary
submit/status never wait for consumption. Initialization and stop control polls
have calibrated TSC and iteration bounds. This initial synchronous stop interface
must not be used in the normal Doom tic path. Static DMA queues, headers and
statuses stay pinned for the boot; failed reset quarantines them. A successful
STOP/RELEASE and observed reset is protocol completion, not a physical hardware
fence or proof that downstream speakers have gone silent. No live replacement,
restart continuity, hardware audio or remote audible latency claim is made.

The build script explicitly selects `native-pcm-qemu82`. QEMU 8.2.2 writes the
36-byte PCM_INFO response but reports only the four-byte status header in the
used ring. This option permits only that query/length combination after success
payload and padding validation; generic queue and TX checks remain strict.
Without the option this backend is refused. The observed behavior agrees with
QEMU v8.2.2 `hw/audio/virtio-snd.c` (PCM_INFO handler and process_cmd); no upstream
code was incorporated.

First measured native capture: 96,000 frames, exactly 2 seconds at 48 kHz;
480 Hz left, 800 Hz right, both peak 8,000, no clipped samples or measured
period discontinuities. Native init reported 96,000 accepted/completed frames,
2,105 elapsed ticks before shutdown grace, 969 full-queue retries, clean exit,
and no remaining process resources. QEMU WAV was independently read and measured
by `scripts/audio-wav-check.py`; its negative controls reject short tails,
swapped channels, silence and incorrect amplitude.

An earlier run completed all guest buffers but captured only 95,556 frames.
The producer now waits 50 ticks after device completion before STOP/RELEASE.
This measured QEMU WAV capture grace preserved the full tail in the successor;
it is not a general downstream drain or audibility guarantee. Exact occurrence
and raw evidence pointers are in #96 and the lane checkpoint. Source review is
independent; disappearance, Doom integration and live remote hearing remain
separate outstanding work.

Additional native lifecycle modes use the same driver and producer binary. The
`pcm-death` and `pcm-underrun` measurements below are historical evidence from
the research branch; they were not rerun on these integration heads.

- `pcm-stop` fills the bounded queue and requests stop. Usually buffers are
  pending: STOP returns AGAIN, later submission is refused, completions are
  polled, then stop succeeds and reset is observed (`PCM STOP PENDING OK`).
  The device may legally complete every buffer before STOP; STOP then withdraws
  at once and the fixture checks submission and status are refused
  (`PCM STOP DRAINED BEFORE STOP OK`). That line reports the frames the
  fixture had accepted; it establishes withdrawal and the refusal of later
  submission and status, not complete downstream capture of those frames.
  Which branch a guest takes depends on device timing, so both are driven
  with controlled completion timing on the host: `make pcm-stop-fixture-test`
  (`user/src/pcm_stop.rs`). Guest evidence on the integration heads (kernel
  640980a and later) exercised only the Pending branch: `PCM STOP PENDING OK
  frames=2400`. The already-drained branch has controlled host coverage only.
  Historical measurement (research run 388538c1, before the fixture repair):
  2,400 frames in 206 ticks including the 50-tick capture grace.
- `pcm-death` delegates playback to a child, retains only a read handle in init,
  verifies the child cannot mint root authority, then kills it with buffers
  pending. Status fails and reopening is refused after last-writer cancellation.
  The last pre-kill status snapshot had 960 submitted frames and two pending
  buffers. Completion can race with kill; this is not an atomic measurement at
  termination. The historical serial label `pending_at_kill` means that snapshot.
- `pcm-underrun` drains the guest queue, deliberately waits 150 ticks, and resumes.
  The measured pause was 151 ticks; all 96,000 frames subsequently completed and
  were captured with exact waveform continuity. QEMU WAV inserted no silence:
  this demonstrates recovery of sample delivery after an empty queue, not a
  listener's wall-clock gap or an observed device XRUN event.

Historical evidence, not reruns: all three research-branch guest runs exited
zero with no remaining process resources. Captures and serial receipts are in
the research lane registry under runs 388538c1 (stop), 06e71b8d (death), and
89479f4d (underrun). Each build is `sh scripts/audio-build.sh MODE`; execution
and cleanup retain the same isolated-host requirements.

For the isolated headless Doom experiment, build the external worker with
`ABSD_PCM_PLAYBACK=1` and `EXTERNAL_KERNEL_FEATURES=native-pcm-qemu82`, and
add the `pcm-enable` option after the existing durable boot mode. This option
initializes audio without replacing that mode; device refusal leaves the ordinary
workload able to run. Only the selected external worker, with `served()` false,
receives a playback grant. Init duplicates read/write rights into its startup
vector, labels that position with private role 0xf0, and closes its own copy.
The matching experimental platform runtime must enable `native-pcm-experiment`.
The default runtime rejects this private role. This does not grant playback to
sshd or arrange inheritance by its session children.

### One-session SSH experiment

`ABSD_PCM_PLAYBACK=ssh-demo` opts a served external worker into the private
startup playback role. Its image must be the experimental SSH server built
with `native-pcm-delegate`; the ordinary `1` setting remains headless only.
The server delegates only when spawning the exact `/bin/doomgeneric` path.
A failed kernel spawn returns the grant to the server. A successful spawn
spends it, closes the server's writer, and never restores it after a later
startup failure. By design other commands receive no playback handle and a
second audio session requires a fresh guest; those exclusions are covered by
host lease tests only. The executable filesystem and server image are pinned
experiment inputs; the pathname is a routing rule, not an image identity check.
A dead holder's handles are released when the kernel reaps it.

Guest evidence: one successful direct-exec chain, occurrence
`3b2d182d-be73-4897-9002-c2f299b6e4ca` on execution_host (QEMU 8.2.2/KVM, worklet
browser audio), reviewed revisions kernel 4af9b58 and platform 946917e2.
Identities: served ISO sha256 `777a9059d83bdbcd7ca313f806c80ac20a922bd2956a5f429f6c44d70b9dffda`
(features `frame-admission-v0,native-pcm-qemu82`, options `net fsd served
pcm-enable`, `ABSD_PCM_PLAYBACK=ssh-demo`); delegate sshd
`59514bff031a458f9de88873c1fadd9aa058af394d4ad0b6262455368f2beb50`; Doom
executable `a207942464966fd2825b6acbb60bb388b8c20ae36016960d58c72c7e1f44eaf4`
(opt-in C kit 946917e2); session configuration
`cc2bf50318fa5bc62ac5b5fad90d61fb7bf548d36179a7f3bcc4138c1ef99b6a`.
The kernel initialized the device, sshd started one `/bin/doomgeneric` child
without spawn right, and the child obtained playback (`PCM_DOOM_READY`).
1,643,040 frames were submitted, device-completed, captured by QEMU WAV,
forwarded byte-identically and rendered by the browser; pistol samples match
the WAD. The child and SSH exited 0, the session was reclaimed
(`children_started=1`), and remote resources and the guest key were retired.
This is one bounded automated run: not physical audio, live hearing, hardware
fencing, restart continuity or live replacement.

Not verified in a guest on these heads:

- a second `/bin/doomgeneric` launch being refused the grant;
- an unrelated command or path receiving no grant;
- sshd restart (no fresh grant expected);
- delegation failure paths (failed spawn restoring the grant, startup failure
  after spawn not restoring it, failed parent close);
- grandchild refusal (relies on the direct-exec policy withholding spawn);
- the headless-worker chain with `ABSD_PCM_PLAYBACK=1`;
- `pcm-death` and `pcm-underrun`;
- the live already-drained STOP branch.
