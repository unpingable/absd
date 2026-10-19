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
- The fixed Ethernet receive policy also admits IPv6 all-nodes
  `33:33:00:00:00:01` and solicited-node `33:33:ff:*:*:*` destinations for
  userspace Neighbor Discovery. Arbitrary configured IPv6 addresses span
  every e1000 multicast hash entry, so all 128 MTA words are set. Hardware
  therefore DMA-receives all multicast, although RCTL.UPE/MPE remain clear.
  QEMU's hash lookup can also admit unrelated unicast after an exact-address
  miss, so the station-MAC software check is necessary too.
  Before delivery, `accept_rx_destination` preserves only the station MAC,
  broadcast and those two multicast patterns. Other destinations increment
  `rx_refused` and recycle their descriptors; each poll still examines at
  most 32 descriptors. Unrelated multicast can consume ring capacity and
  increase `rx_missed`; this is not selective hardware multicast filtering.
  Frames previously discarded by hardware can now increment `rx_refused`,
  including during IPv4 use. The counter layout and increment mechanism stay
  the same, but its observed population changes with this receive policy.
  The driver parses no IPv6 or ICMPv6 fields, selects no configured address,
  creates no endpoint grant and changes no NIC syscall ABI. Userspace owns
  address membership, protocol validation and application authority.
- Polled. A send writes one descriptor, moves the tail, and polls that
  descriptor's done bit (spin, then `hlt`, at most 100 ticks; with a
  descriptor held for lack of carrier, one more bound for it once carrier
  returns). A receive looks at the next descriptor's done bit; blocked
  receivers are checked
  from the scheduler and the idle loop on every timer tick.

Everything the device writes is untrusted (`src/e1000_ring.rs`, host
tested): a receive descriptor is delivered only if it is done, ends the
packet (no frame spans descriptors), has no error bit set, and its length
is 14..=1514. Anything else is counted in `rx_refused`, recycled, and never
reaches a process (QEMU hands the driver 1515..1518-byte frames, which it
accepts without long-packet mode: `NIC RX REFUSED length=1518`). A receive
or transmit head register outside its ring disables the NIC: receive and
transmit are turned off, `NIC DISABLED reason=...` is printed once, and
every later send and receive returns `ERROR_IO`.

A send's bound that expires with the link up (`STATUS.LU` set) is a
device outcome and disables the NIC the same way (`NIC DISABLED
reason=tx-timeout`). A bound that expires with the link down is a link
outcome (the service-lifecycle record's §10): `nic_send` returns `-100`
(`ERROR_NO_CARRIER`), `tx_errors` counts it once, the NIC is not
disabled, and the descriptor stays the device's (`src/e1000_ring.rs`
`TxSlots`, host tested). While it is held, a send with the link still
down is refused with `-100` at once: nothing is posted, nothing waits,
no counter moves. Once its done bit is seen (by a send or `nic_info`) it
is counted in `tx_frames` and sending resumes, so a frame whose sender
got `-100` may still reach the wire. With carrier back and no done bit,
the next send waits one fresh bound for it: expiry with carrier present
throughout that bound is a device outcome; a loss seen during it keeps
the descriptor held (`-100`, no further count). A device that fails
across a carrier loss is therefore first reported as a link outcome and
becomes a device outcome at the next send whose bound runs with carrier
present throughout: one bound later on a link that stays up, later on
one that keeps dropping, and not at all if nothing more is sent (the one
held slot stays the device's). A held descriptor is never rewritten or reclaimed without its
done bit; a NIC disabled while one is held abandons it for the boot.
Carrier is read when the descriptor is posted, at each tick-paced poll
of the bound (about 1 ms apart; not during the first microseconds of
spinning), and at expiry; a loss seen at any of them makes the expiry a
link outcome. A loss shorter than a poll interval can be missed, and the
expiry is then a disable, as before this rule: a missed loss errs toward
a device outcome. (A loss that is seen errs the other way, as above: a
device failure across it is reported as a link outcome until a bound
runs with carrier throughout.)
QEMU's device completes a transmit descriptor with the link down and
drops the frame, so without the qualification fixture (Verification,
step 5) the link branch is never reached here. Whether a physical NIC
holds descriptors without carrier is an open per-device obligation:
no physical NIC is qualified for this rule until the record's §10 (c)
observation on the named machine.

The opt-in I219 backend (`net-i219`, docs/hardware/I219-NATIVE.md)
applies the same rule through the same `TxSlots` (`src/i219_ring.rs`
`I219Tx`, `send_step`): carrier is `STATUS.LU`, read at post, at each
poll of its bound (at most 100 polls about 1 ms apart and 100 ticks), and
at expiry. It also refuses before posting when its carrier decision
reports no carrier (`-100`, nothing posted, no counter), so it holds a
descriptor only when carrier drops during a bound. A done bit with
completion-error bits is counted in `tx_frames` and then disables the
NIC; a stalled clock disables it, never `-100`. This is host-tested
development evidence only: no I219 has been observed holding or
completing a descriptor without carrier (§10 (c) on the Z2 is open), and
the transmit-hold fixture is refused under `net-i219`.

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
| 33 | `nic_send` | `RDI=nic handle`, `RSI=frame`, `RDX=length` | Write right. One frame of 14..=1514 bytes (destination MAC first, no FCS), zero-padded to 60 on the wire. Returns 0 once the device reports it done. `-22` for a length out of range (counted in `tx_refused`; nothing reaches the device), `-14` for a bad address, `-5` once disabled; `-100` when the link has no carrier and the frame was not reported done (the NIC stays enabled; while a descriptor is held, later sends are refused with `-100` at once until it completes or carrier returns). Order: `-5`, `-22`, `-100`, `-14`. |
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
5. `net-probe nic-tx-hold` with `nic-reflect.py --tx-hold`: the link is
   down before the probe and the kernel arms its transmit-hold fixture
   (`NIC TX HOLD FIXTURE ARMED mode=release kind=tctl`): a descriptor
   posted while `STATUS.LU` is clear is held by clearing `TCTL.EN` before
   the tail moves, and the transmitter resumes once carrier is back.
   `nic-probe`'s first send waits out its bound and gets `-100` with
   `tx_errors` 1 and the NIC enabled; the second is refused in under 50
   ticks with no counter moving; receive still polls; nothing reaches the
   wire (`NIC PROBE TX HELD`). The harness raises the link; the held
   frame and the next one reach the wire in that order (`NIC PROBE TX
   RELEASED tx_frames=2 tx_errors=1`, `NIC TX HOLD OK`), and no `NIC
   DISABLED` is printed.
6. `net-probe nic-tx-hold-stuck`: the same, but the fixture never resumes
   the transmitter, so the bound that runs once carrier is back expires
   with carrier present: `NIC DISABLED reason=tx-timeout`, `-5`,
   `tx_errors` 2, nothing on the wire (`NIC TX HOLD STUCK DISABLED OK`).

The transmit-hold fixture is a QEMU qualification device only, like
`nic-ring-fault`: it stands in for a device that holds a descriptor
without carrier, which QEMU's is not, so steps 5 and 6 show the driver's
rule, not any device's behaviour: the fixture decides when the
descriptor completes, where a real e1000 completes it or not on its own.
The fixture resumes the transmitter only when the driver next looks (a
send's bound or `nic_info`'s reap), not inside a running bound. In step
5 `nic-probe` polls `nic_info` while it waits for the link flag, so on
QEMU the held descriptor is almost always released and counted by that
reap; the send-path release (the next send's bound finding it done once
carrier is back) is what the host tests of `TxSlots` cover, not what
these runs exercise. A link loss inside the natural descriptor window
(microseconds under QEMU) cannot be landed from the host; the fixture
opens that window deliberately. The kernel refuses the options outside
a `net`/`net-probe` boot, beside `nic-ring-fault`, and in the physical
profile, and announces them when armed; no physical or operator image
recipe carries them. Given in a boot whose NIC is absent or refused,
they arm nothing and the boot fails visibly: no `NIC TX HOLD FIXTURE
ARMED` line, and init refuses to run without a NIC (`init: FAILED at no
NIC`). The boots of steps 1–4 must print no `NIC TX HOLD` or `NIC PROBE
TX` line.

The protocol-level matrix (ARP, IPv4, ICMP echo, malformed packets, TCP
listen/stream/backpressure/reset/reconnect with host clients through
`-netdev user` forwards) lives with `absd-net` in the platform repository
(`scripts/net-matrix.py`).

## Limits

Polling on the timer tick adds up to a millisecond of receive latency;
QEMU's user network can deliver bursts faster than 32 descriptors drain
between ticks, and those frames are counted in `rx_missed` (TCP repairs
them). One NIC, one owner process, a fixed multicast receive policy with no
runtime filter programming, no checksum or segmentation offload, no VLANs.
The 82540EM is QEMU's; a
laptop's I219 (e1000e) or I225 (igc) is a different driver.

### IPv6 multicast prerequisite: source scope and evolution

This source change is based on kernel candidate 5
`2bfe825a980379583467e80572561f23834435c8`, for the static IPv6 UDP/DNS
consumer recorded in the internal tracker.
Its result identity is the commit containing this section and the changed
`src/e1000.rs` / `src/e1000_ring.rs` blobs. The three receive-destination unit
tests cover station/broadcast preservation, arbitrary solicited-node suffixes
and refusal of other multicast groups. All three passed in kernel workspace
run `80781ce6-6804-4cff-a3ba-ac4c524e2d83` at source
`9b1f7b9d060b973121f3885e0ea15c819bc98b9f` (272 tests passed, one existing
benchmark ignored). They alone do not establish DMA reception, NS/NA
interoperability or live SSH coexistence. Native run
`b860a19b-ba62-4ead-b1a5-f5a7cddffc92` observed Linux/native NS/NA and DNS A/AAAA,
but its strict zero-refusal predicate failed on two filtered frames. Its capture
contains normal Linux MLDv2 setup traffic outside this filter's admitted groups;
the failed verdict remains unchanged. Live SSH coexistence remains unrun.
No physical NIC support, release promotion or supported ABI change follows.

Destination refusals now print `NIC RX FILTERED dst=...` within the existing
first-four-refusals diagnostic budget, separately from descriptor-error reasons.
The `NETWORK LINK OK` line is the existing readiness marker. `NicInfo` and
syscall bytes are unchanged. The shared refusal counter now includes software
destination refusals for frames newly admitted by the broader hardware filter;
this is a material observation change for every consumer, IPv4 included.
The reason lines are
bounded diagnostic observations, not an exhaustive event stream after that
budget is spent. A successor qualification case must keep its raw capture,
record its readiness-observation uncertainty, classify all counted peer frames,
and require exact capture/counter correspondence. Ambiguous readiness or a
counter mismatch is inconclusive/failing, never an excuse for a historical pass.
The serial-only addition does not change admission, authority or replacement
state; source diff plus compiled/native replay suffice for this correction's
formalization consideration, owned by S2. It proves no physical receive timing.

The device's stable logical identity is its claimed PCI function; MAC/filter
registers and rings belong to the current implementation generation. A future
replacement must fence old handle/request authority, stop polling/submission,
establish DMA exclusion before retiring buffers, and reconstruct the fixed
filter plus fresh authorized userspace address/neighbor state. There is no
exported state schema or live-transfer mechanism here. A successor needs external
validation of its filter, rings and consumers before commit; otherwise refuse
replacement. Restoring an older source/kernel cannot undo emitted traffic or
revive fenced grants. Old-generation resources retire only after exclusion and
the owning consumer's retirement conditions, not on a software timeout alone.

Formalization consideration: S2 owns the proposition that this fixed MAC
predicate admits precisely the station, broadcast, all-nodes and solicited-node
patterns, independently of protocol authority. Practical bounded vector tests
and review are sufficient for this small stateless equality predicate; no new
concurrency or recovery state is introduced. Hash broadening, ring exhaustion,
device behavior and end-to-end grant enforcement are outside that proposition
and need native qualification. The source/result identities above bound this
consideration. The [Intel 8254x manual](https://www.intel.com/content/dam/doc/manual/pci-pci-x-family-gbe-controllers-software-dev-manual.pdf),
sections 13.4.22 and 13.5.1, specifies the MTA hash; every selectable hash uses
only variable solicited-node suffix bits. QEMU's
[group-filter implementation](https://gitlab.com/qemu-project/qemu/-/blob/7c89e226f878539b633dde3fd9c9f061c34094e3/hw/net/e1000x_common.c)
also illustrates the unicast hash fall-through. No driver or protocol source
was imported for this change.
### QEMU cold receive delay

QEMU's e1000 model gates reception for one second after every write to
the receive control register: `set_rx_control` arms a 1000 ms timer on
QEMU's virtual clock, and while it is pending `e1000_can_receive` is false
and `e1000_receive` queues the frame (hw/net/e1000.c, unchanged from 8.2.2
through current master; QEMU's e1000e model has no such timer). The driver
writes RCTL in the probe, so on QEMU a guest receives nothing for the first
second after `NIC CONTROLLER`: frames that arrive earlier are delivered
when the timer fires, and a tap backend stops reading behind the queued
frame, so a `filter-dump` capture on the netdev also shows later inbound
frames late. Measured (recorded internally, QEMU 8.2.2, Vultr bare metal, three
boots per point): a frame sent at any time before the gate opens is
reflected 1000-1004 ms after the RCTL write, under TCG and KVM alike; a
frame sent after it is reflected within 4 ms (TCG) or 1-16 ms (KVM). The
kernel's own receive path is that small term. The "~700 ms cold receive"
seen by the S2 lanes is this gate: one second less the time from the probe
to the first inbound frame. A test that needs a reply sooner than one
second after the probe must wait for the gate (or warm the neighbour after
it); the 82540EM itself and the I219 path have no such delay.
`make nic-cold-rx-measure` reruns the measurement (scripts/nic-cold-rx.py;
not part of `make check`).

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
