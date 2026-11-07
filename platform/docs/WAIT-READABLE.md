# Supported readable waits

The kernel API and Rust/C bindings are documented in `wait_readable(2)`.
This additive ABI 1 call uses syscall 0x7fa8 and a fixed maximum of 11 handles.
The runtime always forwards the request, so an older kernel returns -38 even
for an empty slice. There is no private environment or kernel-feature opt-in.

FSD serving startup probes an empty set before channel validation or writable
startup. A supported kernel returns -22. An old kernel returns -38, causing
`FSD FAILED kernel lacks wait_readable` and exit 3; unexpected answers also
refuse. The independent finalization modes precede this serving-only probe.

The intended 18 client slots, control and logger total 20 channels. Every
serving pass visits all active channels with the existing round-robin and
transfer/dispatch bounds. Each idle wait selects at most 11 eligible requests
in cursor order; the idle cursor advances 11, covering every channel within
two consecutive idle waits. Omitted readiness can cost one extra finite wait:
argument 1 means up to two delivered ticks plus scheduling, not a wall-clock
bound. Buffered work prevents sleep even beyond the selected subset. Pending
replies retain bounded retry; ended requests leave the set until rebinding.
Partial-frame recovery still requires the existing two-tick quiet period.
The control EOF path preserves the bounded logger drain and final commit.

The source review and correctness/compatibility controls apply to the final
paired kernel/platform revisions. The private spike's performance results are
historical evidence, not a new-pair performance or idle-CPU claim. See
[release compatibility](RELEASE.md#supported-readable-waits) and
[SDK bindings](HOST-SDK.md#bounded-readable-waits).
