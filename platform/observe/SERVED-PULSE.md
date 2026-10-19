# Native Pulse on the served operating path

`pulse-frame-pressure` runs the existing ABSD-owned Pulse frame-pressure
producer, receiver and resolver as an ordinary program launched by SSH or the
native shell. It uses that process's existing FSD channels. This entry point neither requests nor explicitly mounts raw storage; the
inherited runtime may still receive or mount a read-only startup block handle,
so no claim that the process holds no raw storage authority follows. The carried Pulse source, family schema, signatures, thresholds,
clock identity and sixty-second validity are unchanged.

Build in an isolated platform checkout with the existing pinned Rust sysroot:

```sh
ABSD_PROFILE=core scripts/stage-library.sh
ABSD_PULSE_SOURCE=/absolute/pinned-monitor-source scripts/build-pulse-served.sh
```

The source repository must contain the exact Pulse commit/tree that the
existing `stage-pulse-observe.sh` verifies. The new executable is
`pulse-frame-pressure.elf`; install it as `/bin/pulse-frame-pressure` in an
ordinary served image. It is not automatically added to the accepted base
release or U1 image. The original direct-block qualification executables and
runners remain unchanged.

Provide the existing `pulse.absd_host_frame_pressure_support_config.v1`
configuration, its enrolled signing key and separate outgoing/receipt
locations inside the process's authorized writable workspace. No new config
format or implicit diagnostic admission is introduced. For example:

```text
pulse-frame-pressure cycle --config /home/operator/pulse/config.json --acquisition-id sample-1
ro pulse-frame-pressure resolve --config /home/operator/pulse/config.json < /home/operator/pulse/query.json
```

`cycle` loads one configuration, calls the real Pulse `produce`, then `ingest`,
and prints their existing evidence/receipt IDs. Repeating an acquisition ID
uses the family's existing idempotence rules; it is not a new sample. A new
sample needs a new acquisition ID. `resolve` takes the existing bounded
Nightshift query on stdin and writes the existing canonical support object.
It invokes no producer, helper, NQ, Nightshift or mutation command.

Use the existing native shell's `ro` prefix for the resolver: FSD then enforces
read-only mounts for its process. `ro ... cycle` with a fresh acquisition ID must refuse to write, and
`nofs ...` must refuse startup rather than fall back to a block mount. The
outer SSH account still has ordinary operator authority; narrowing a child is
not a restricted SSH account or an ambient authority grant.

The carried key-mode adapter reports ABSD's read-only/writable metadata as
0o400/0o600; it does not establish Unix ownership or per-user secrecy. Signing
key custody on this path comes from the actual FSD workspace/reader authority
and the operator's custody of the fixture. Other processes allowed to read
that workspace may read the key; a read-only resolver need not read it, but
read-only access alone does not hide it. Signatures do not prove independent
administration or an exclusive key holder.

This provides a real native consumer of ABSD process start, stdin/stdout,
boot identity/time, frame observations and persistent FSD files. A later boot
retains the files but cannot revive old-boot support. Expiry is checked on the
ABSD boot clock. An observation is not NQ judgment or action authority; the
family's configured diagnostic pins must not be described as a real NQ
execution when they are fixture pins.

Formalization consideration: the new entry point composes existing bounded
operations without adding a persistent state machine or state schema.
Argument/config refusal tests and native served/read-only/no-filesystem,
receipt expiry and reboot cases check the new construction correspondence.
The producer's observations and receiver's arrivals are separate clock reads,
not an atomic system snapshot. Process completion is not proof of safe kernel
or hardware generation transfer. Existing boot-clock refusal fences old
support; no identity or authority rebind is implied. Decision owner: U2 lane
maintainer; exact source and result identities are in its run receipt.
