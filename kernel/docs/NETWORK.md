# Network interface

The operator opened networking for the SSH tranche (2026-09-26). The shape
is the smallest one that gives a userspace process TCP: the kernel drives
one NIC and moves whole Ethernet frames through a handle; the protocol
stack (ARP, IPv4, ICMP echo, TCP) runs in the process that holds that
handle. There are no kernel sockets, no socket object, no general driver
framework, and no IPv6, UDP, DNS, or DHCP. Addresses are static.

Why not a kernel stack: there is no kernel heap and TCP state is exactly
the growth the guardrails keep out. Why not a userspace driver: no IOMMU is
programmed, so a device that a process could point at memory could DMA
over anything. The kernel therefore keeps the descriptors, the buffers,
and every device-written field; a process only ever hands it bytes.

## Device

`src/e1000.rs` drives one Intel 82540EM (QEMU `-device e1000`), found by
PCI vendor and device (8086:100e) and claimed through `pci::claim` (below).
It is probed only when the boot command line carries `net` (as an option,
for example `durable=2 net`) or the mode word is `net-probe`; every other
boot, and every physical ISO entry, leaves network devices untouched.

- Reset (`CTRL.RST`, bounded wait), all interrupts masked (`IMC`, PCI
  INTx disabled), MAC from receive address 0 (refused by name,
  `NoMacAddress`, when not marked valid), link up asked for (`CTRL.SLU`)
  and awaited for at most two seconds. A link that is not up by then is
  not a refusal: the device initialized, so it is granted with the link
  down, `nic_info` reads the link live from `STATUS.LU`, and frames flow
  once carrier returns with no re-probe (a cable unplugged at power-on
  is a degraded machine, not a dead boot; on QEMU, see the transmit-bound
  note below for physical devices). Only an absent or unclaimable device
  (the function owned by another driver, no memory BAR, a mapping
  refusal), a reset that never completes, and a missing MAC refuse the
  NIC.
- One receive ring of 32 and one transmit ring of 16 legacy descriptors,
  each ring in its own page, each descriptor owning one 2 KiB buffer, all
  static and identity-mapped (the address is the bus address).
  `RCTL`: broadcast accepted, CRC stripped, 2 KiB buffers, long packets
  and promiscuous modes off.
- Polled. A send writes one descriptor, moves the tail, and polls that
  descriptor's done bit (spin, then `hlt`, at most 100 ticks). A receive
  looks at the next descriptor's done bit; blocked receivers are checked
  from the scheduler and the idle loop on every timer tick.

Everything the device writes is untrusted (`src/e1000_ring.rs`, host
tested): a receive descriptor is delivered only if it is done, ends the
packet (no frame spans descriptors), has no error bit set, and its length
is 14..=1514. Anything else is counted in `rx_refused`, recycled, and never
reaches a process (QEMU hands the driver 1515..1518-byte frames, which it
accepts without long-packet mode: `NIC RX REFUSED length=1518`). A receive
or transmit head register outside its ring disables the NIC: receive and
transmit are turned off, `NIC DISABLED reason=...` is printed once, and
every later send and receive returns `ERROR_IO`. A send whose descriptor is
not done within its bound disables it the same way. QEMU's device completes
a transmit descriptor with the link down and drops the frame, so that bound
does not fire for a missing carrier here; whether a physical NIC completes
descriptors without carrier is an open per-device obligation (the
service-lifecycle record's carrier-loss requirement), and until it is
observed on the named machine a pulled cable on such hardware would read
as a device failure.

Boot markers: `NIC CONTROLLER pci=BB:DD.F vendor=8086 device=100e
mac=...`, then `NETWORK LINK OK rx_descriptors=32 tx_descriptors=16
buffer_bytes=2048` or `NIC LINK DOWN AT PROBE rx_descriptors=32
tx_descriptors=16 buffer_bytes=2048` (granted either way), or `NIC
UNAVAILABLE <reason>` (then nothing is granted).
Boots that end through the external/durable accounting also print `NIC
STATS rx_frames=... rx_refused=... rx_missed=... tx_frames=...
tx_refused=... tx_errors=... flags=...`.

## PCI device ownership

The DESIGN-INFLUENCES PCI tripwire fired with this second PCI consumer.
The rule, now in `src/pci.rs`: a function has at most one kernel owner for
the boot. A driver `claim`s the function before it maps a BAR or enables
bus mastering; a second claim is refused by name (`Owned("nvme")`). BARs
are read with `memory_bar(function, n)`; `find_id(vendor, device)` finds
by identity. DMA targets only static kernel memory. Interrupts stay
masked; there is still no MSI, interrupt routing, or enumeration model.

## ABI (`abi/src/nic.rs`)

`Object::Nic` is the one probed NIC. Its rights: read (receive and
`nic_info`) and write (send). Like the block device it is not reference
counted and cannot be created by a process.

| Number | Name | Arguments | Result |
|---:|---|---|---|
| 32 | `nic_info` | `RDI=nic handle`, `RSI=64-byte record` | Read right. `{mac[6], flags u16, rx_frames, rx_refused, rx_missed, tx_frames, tx_refused, tx_errors}` (little-endian u64 counters from boot). Flags: 1 link up, 2 disabled. |
| 33 | `nic_send` | `RDI=nic handle`, `RSI=frame`, `RDX=length` | Write right. One frame of 14..=1514 bytes (destination MAC first, no FCS), zero-padded to 60 on the wire. Returns 0 once the device reports it done. `-22` for a length out of range (counted in `tx_refused`; nothing reaches the device), `-14` for a bad address, `-5` once disabled. |
| 34 | `nic_receive` | `RDI=nic handle`, `RSI=1514-byte buffer`, `RDX=timeout ticks` | Read right. The next accepted frame; returns its length. The whole 1514-byte buffer must be writable user memory, checked before a frame is taken, so a frame is never consumed and lost. Timeout 0 polls (`-11` when none is waiting); a positive timeout blocks (`WaitKind::Nic`) at most that many ticks (`-110`). There is no unbounded receive. `-5` once disabled. |

Frames larger than `read`/`write`'s 256-byte transfer are why these are
frame calls rather than a pipe.

## How a process gets the NIC

In a `net` boot the kernel's root grant to init carries the NIC handle in
`RCX`, init's fourth entry argument (`Start.nic`), beside the block handle
in `RSI`. Init hands it to exactly one process: in a durable boot, each
worker generation (read and write rights), never the reader and never a
brokered child. The worker learns it from its startup record, role 12
(`nic`) in docs/BROKER.md; a `net` worker therefore always gets the record
shape, with or without a broker channel (and, as every durable worker, the
spawn right exactly when no broker policy is embedded):

    [startup, input, block, step, nic, (request, reply, slots...), console]

A worker holding the NIC is a server paced by its peers, so in a
qualification boot init gives it an hour (`NET_WAIT_TICKS`; a build can
shorten it) instead of the ordinary two-minute deadline; a served boot's
worker has none (docs/PROCESS-STARTUP.md, "Served boot and orderly
shutdown").
Such a worker (without a broker policy) starts programs itself, and their
descendants can outlive them: the kernel has no process-tree kill, so
orphans come to init. While the worker runs, init reaps ended orphans
every `ORPHAN_REAP_TICKS` (`INIT ORPHAN REAPED pid=N`); otherwise each
would hold a process-table entry until the boot ends. Live orphans run to
their own end.
Init holds its own NIC handle for the rest of the boot and never uses it.
In a `net fsd` boot the worker gets the same NIC role but no block handle:
its storage is the file server's, through the channels init minted for it
(docs/PROCESS-STARTUP.md, "File server").

`net-probe` boots run the embedded `nic-probe` program instead, handed the
NIC through legacy `spawn`.

## Userspace stack

The Rust platform repository (`absd-rust-std`) carries `absd-net`: smoltcp
0.14.0 (`alloc`, `medium-ethernet`, `proto-ipv4`, `socket-tcp`,
`socket-icmp`, `auto-icmp-echo-reply`) over these calls, driven by a poll
loop on the tick clock. Its API and the SSH server shape are documented
there. A connection is a smoltcp socket in the process; nothing else in the
system can see it.

## Verification

`make net-test` (not part of `make check`; it needs `-netdev dgram`):

1. `net-probe` boot with `scripts/nic-reflect.py` as the only other host
   on a `-netdev dgram` unix-socket wire. `nic-probe` checks every refusal
   first (lengths 0, 1, 13, 1515, huge; kernel and null pointers; a
   receive buffer running off the stack; poll and timeout on an idle link;
   read-only and write-only duplicates; a stale handle), then reflects
   `0x88b5` frames. The harness requires a hello from the printed MAC, 13
   frames of 15..1514 bytes and a burst of 24 back byte for byte, and no
   answer to 1515, 1516, and 1518-byte frames, then exact counters
   (`NIC PROBE REFLECTED frames=38 ... rx_refused=3`).
2. The same boot with the link down before the kernel probes
   (`nic-reflect.py --link-down`: QEMU started stopped, QMP `set_link`
   off, then `cont`). The kernel prints `NIC LINK DOWN AT PROBE` and
   grants the NIC; `nic-probe` finds the link flag clear and the NIC not
   disabled, poll and timeout receive nothing, and one hello sent with
   the link down is completed by the device (`tx_frames` 1, `tx_errors`
   0) and never reaches the wire (`NIC PROBE LINK DOWN mac=`). The
   harness raises the link; `nic-probe` sees the flag turn on without
   re-opening anything (`NIC PROBE LINK UP`) and the whole reflection of
   step 1 follows (`tx_frames=40`, `flags=1`). The healthy boot of step 1
   must print neither link line.
3. `net-probe nic-ring-fault`: the kernel writes 35 into the device's
   receive head register before init starts (`NIC RING FAULT INJECTED
   rdh=35`); the first receive finds it, the NIC is disabled (`NIC
   DISABLED reason=rx-head-outside-ring head=35`), and `nic-probe` requires
   `ERROR_IO` from receive, poll, and send and the disabled flag (`NIC FAIL
   CLOSED OK`). The option is honored beside `net` in a durable boot too,
   so the platform matrix can run a stack over a NIC that disables itself
   at its first ring access (`absd-net`'s dead-NIC pacing). It is a QEMU
   qualification device only: the out-of-ring head points the device at
   zeroed descriptors, which QEMU skips and real hardware need not, so no
   physical or operator image recipe carries it.
4. `net-probe` with `-nic none`: `NIC UNAVAILABLE Absent`, init refuses to
   run without a NIC, and the boot fails as it should.

The protocol-level matrix (ARP, IPv4, ICMP echo, malformed packets, TCP
listen/stream/backpressure/reset/reconnect with host clients through
`-netdev user` forwards) lives with `absd-net` in the platform repository
(`scripts/net-matrix.py`).

## Limits

Polling on the timer tick adds up to a millisecond of receive latency;
QEMU's user network can deliver bursts faster than 32 descriptors drain
between ticks, and those frames are counted in `rx_missed` (TCP repairs
them). One NIC, one owner process, no multicast filter programming, no
checksum or segmentation offload, no VLANs. The 82540EM is QEMU's; a
laptop's I219 (e1000e) or I225 (igc) is a different driver.

## Future architecture direction — 2026-10-07

Operator decision; planning/documentation only. Existing implementation and its
qualification remain the e1000/QEMU path above. **VirtIO-net is the preferred
first implementation of the future device abstraction**, not an already present
driver and not disposable scaffolding. Bare-metal networking is deferred. The
Z2 is a future exact-hardware acceptance/proving target, not a present driver of
network architecture or a dependency of native-persistence work. No stack,
NIC driver, PCI/DMA expansion or qualification campaign starts with this note.

### Sequence and scope

| Stage | Purpose and boundary |
| --- | --- |
| 1. VirtIO/QEMU | Develop the network/device ownership abstraction and stack/service semantics under an explicit VirtIO contract. Preserve current e1000 evidence; no replacement is implemented by this decision. |
| 2. Shared native substrate | After the virtualized architecture is stable, develop the missing PCI enumeration, BAR mapping, MSI/MSI-X, interrupt routing, DMA allocation/mapping, IOMMU domains where supported, reset/lifecycle and epoch/quiescence machinery. Existing minimal PCI claims/static DMA are inputs, not proof this substrate is complete. |
| 3. One native reference NIC, preferably with PCI passthrough/VFIO | Choose a well-documented, relatively simple NIC later. Exercise real native descriptors/DMA while retaining VM containment/debugging. Ask whether the abstraction survives real PCIe/DMA behavior; do not invent stack, DMA, interrupt/IOMMU policy and a complex driver together. |
| 4. Bare-metal NIC qualification | Qualify the understood driver/abstractions on an exact admitted target. Z2 may be that target; no I219 variant, device family or physical support is selected/earned by this note. |

The intended rung is `VirtIO/QEMU -> native driver under PCI passthrough ->
native driver on bare metal`, with shared native substrate work before the native
driver. Passthrough is preferred where practical, contingent on suitable device,
reset/isolation and host setup. It is intermediate qualification, not equivalent
to bare metal. None of these future stages is dispatched or scheduled here.

Develop as much as possible in the VirtIO stage: Ethernet, ARP, IPv4/IPv6,
UDP/TCP, routing, socket/user-facing semantics, RX/TX lifecycle and ownership,
reset/restart, backpressure/resource exhaustion, interrupt/polling behavior,
service isolation, malformed packet/refusal handling and bounded failure
injection. This lists the future scope, not a promise that all protocols must
arrive together. Current IPv4/TCP/ARP/ICMP and static configuration are reused;
IPv6, UDP, general sockets and wider routing remain unimplemented/deferred.
Physical NIC/firmware behavior can remain outside ABSD's implementation boundary
in this phase, with the explicit VirtIO device contract as the dependency.

### Network observations and delivery

Networking is not persistence. Normal packets/buffers are transient and can be
lost/retried; persistence can retire the only previous recoverable state. Do not
import filesystem durability states or retirement classes into packet handling.
Network operations and remote application effects still need precise ownership
and retry semantics: retrying a packet or connection never proves an application
effect is reversible or safe to duplicate.

`queued != DMA-complete != wire-delivered != peer-ACKed != application-consumed`

| Observation | Allowed claim |
| --- | --- |
| Queued | Named local transport/network layer accepted data subject to its buffering, backpressure and error semantics; not necessarily submitted to a device. |
| DMA-complete / TX completion | Under the device contract the device no longer needs the associated TX buffer; local ownership may return. It does not prove delivery on the wire or to a peer. |
| Wire-delivered | Only a suitably scoped device/link observation can support a wire claim; ordinary TX completion cannot establish it. It still says nothing about application consumption. |
| Peer-ACKed | The remote transport endpoint acknowledged the relevant transport state, such as TCP sequence space. ACKs do not prove that its application read, accepted or acted on the data. |
| Application-consumed | Requires the application-level protocol/receipt needed by the caller, with explicit meaning and identity. The kernel/stack cannot manufacture this claim. |

These are distinctions, not a mandatory linear observation chain: ACKs may arrive
without independently observing wire delivery, local completions may lag, and
UDP has no transport ACK. The current `nic_send` result above reports device-done
only. Interpret `tx_frames` within its current counter scope, not as remote
application-delivery evidence. User-facing send/socket APIs must preserve the
same distinction when they are later defined.

### Buffer ownership and reset epochs

Future implementations must define TX/RX state machines, descriptor identity,
completion scope, memory ordering/cache synchronization and a single accountable
owner at each transition. Conceptual shapes, not a frozen API:

```text
TX: free -> kernel-owned -> device-owned -> completion-observed
         -> kernel-owned/free
RX: free -> kernel-owned -> device-writable -> completion-observed
         -> kernel-owned (validate/deliver or refuse) -> replenish/free
queue/device epoch N -> stop/quiesce/reset -> establish DMA exclusion -> epoch N+1
```

While device-owned/writable, buffers cannot be reused, freed or modified in ways
forbidden by the device contract. RX ownership returns only after the completion
and visibility rules establish that the device has finished that buffer. Validate
length/status/frame bounds before exposing bytes; delivery to a process does not
automatically repost the same storage while it is still consumed. The existing
copy-based ABI can remain a supported boundary; zero-copy is not required.

Bind descriptors and completion observations to device instance, queue identity,
epoch, descriptor incarnation and buffer/mapping identity. Old-epoch completions
cannot authorize new-epoch reuse or state transitions. Duplicate/stale/unknown
completions refuse the ownership transition; descriptor index alone is insufficient.
Logical invalidation may discard a completion, but **does not stop physical DMA**.
A dead or timed-out epoch therefore retains its buffers until physical access has
been excluded, even if no valid logical completion will ever arrive.

Before old native-device resources are reclaimed, the device-specific sequence
must establish: stop submissions; quiesce/reset queue/device; prevent further DMA;
invalidate/detach mappings where applicable with required translation/in-flight
synchronization; establish that the old instance can no longer access memory;
then reclaim buffers. Merely disabling interrupts, incrementing an epoch, observing
a timeout, writing a reset register or detaching a mapping without its completion
contract is insufficient. If exclusion cannot be established, retain/quarantine
the resources and report refusal/unknown status. VirtIO offers a cleaner contract
for developing these semantics, but still requires verified reset/ownership rules.
The existing e1000 driver's disabled-for-boot/static-buffer path is not evidence
of reusable dynamic DMA or safe restart.

### Narrow device boundary and capabilities

Converge later on a device abstraction for submitting TX, providing/replenishing
RX buffers, processing/polling completions, reset/quiescence and capabilities.
Keep the stack independent of VirtIO transport details and native PCI/BAR/MSI/DMA
machinery. VirtIO-net is implementation #1 of that future abstraction; this note
freezes no trait, ABI or new general driver framework. Preserve the current split:
kernel owns device/memory authority, userspace owns protocol/service state unless
an explicitly admitted later design justifies a change. Device abstraction is not
permission to move unrestricted DMA programming into userspace.

TSO, checksum offload, RSS and other offloads are not inherently incompatible
with ABSD. Represent them eventually as explicit supported capabilities/contracts,
including ownership, packet transformation, validation and observability effects.
Initially disable unsupported or poorly understood features. Require raw-frame
observability only where an actual invariant depends on it, not as a universal
networking prerequisite.

Monotonic scheduling/deadlines and synchronized wall time are separate. Network
architecture and RT correctness do not depend on NTP truth. Qualify invariant
TSC/platform timer behavior for the admitted environment; neither universal
reliability nor universal brokenness is assumed. Time synchronization remains a
separate earned service contract.

FreeBSD/managed-execution interoperability is separate. Networking does not
require importing FreeBSD NIC drivers into ring 0. Any later reuse is an explicit
research lane with device authority, DMA and kernel-assumption analysis, not an
implicit networking dependency.

### Reconciliation and formalization consideration

This refines the existing [administered-networking roadmap](SYSTEM-MATURITY-ROADMAP.md#administered-networking--r2r3)
and [hardware-support view](SYSTEM-MATURITY-ROADMAP.md#bounded-hardware-support-view),
not their accepted source/results. Existing ABSD Program entries for administered
networking and the physical-target I219-LM H4 item hold these future constraints; no duplicate
networking epic is needed. `8086:15bb` (older H4), Z2 `8086:15b7` and QEMU
`8086:100e` are distinct. The older H4 wording “Needs a driver” is qualified by
this later sequencing decision: it is not an immediate native-driver instruction.
The U1 exact-machine NIC census is a future support/acceptance obligation, not a
bare-metal networking prerequisite for current filesystem implementation.
Current Z2 survey explicitly leaves network untouched; its storage/controller
work retains its separate scope.

Formalization consideration: source baseline kernel
`77f75aaf8571d28ab9a7c6aab58d7161a6582393` (`src/e1000.rs`, `src/pci.rs`,
this document, maturity/usability roadmaps and Z2 first-boot note), with unrelated
pre-existing `docs/BOUNDED-JUDGMENTS.md` edits untouched. Result identity is the
NETWORK.md hash recorded in the coordination note. Proposition: scoped completion
can return local buffer authority only within the device/queue incarnation and
cannot establish remote application consumption; reset cannot release old buffers
before DMA exclusion. Owner: ABSD architecture owner / operator; capture owner root.
Practical source review and explicit prose/state shapes suffice for this planning
change. No new runtime claim or model execution. Counterexamples/unknowns include
late completion, descriptor index reuse, reset that leaves DMA in flight, premature
RX repost and transport ACK before application receipt. A later bounded two-epoch
TX/RX model is appropriate when exact reset/mapping semantics are selected;
its device assumptions and implementation correspondence must remain explicit.
