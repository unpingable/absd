# Independent Linux proof for the bounded native TCP server

Current independent bounded acceptance covers runtime `2b2f882c`, proof/peer
`c1377f6c` and native `20b8bf78-03cc-41be-acac-3551cd8198d3` with lane kernel
`ed6a15ea`. The original source-dispatch descriptions below are historical.
Exact results and immutable prior failures are linked by shared registry run
`6d5dc6bd-3886-4c14-a4ad-6f827afc982a`. Composed kernel 7 + platform 10 replay
remains the steward's separate gate.

The retained wrong-port client's `connect-timeout` is not refusal evidence:
its 300 ms timeout elapsed before the guest's 737 ms ARP response, and the
SYN reached the wire only 22 microseconds before the authorized SYN. The
whole capture establishes the actual wrong-tuple SYN and absence of any
SYN-ACK, reset or other response. It does not establish a separate sustained
negative-client interval. The next occurrence should settle ARP first, use
a timeout above one second and separate the wrong and authorized attempts
in time while retaining the strict capture assertion. These are future
qualification changes, not a reinterpretation of the sealed result.

Guest-side filter-drop telemetry and the cause of the initial ARP delay are
open follow-ups on coordination issue 29. Only the existing capture and source
filter predicate establish this run's wire refusal. One native ACCEPT also
does not mean only one pre-ACCEPT transport handshake; see the core document.

This separate, unexecuted case qualifies the one IPv4 server consumer described
in NATIVE-TCP-SERVER.md. Product source is frozen at
2b2f882ce486ed85ba32b21e039e4521c96e2c63, tree
699e237c94e00dec19266ec1fb8c8a02d165e412. The runner does not compile code,
change the kernel or update an older runner/verdict. Source checks are not
host/native execution or independent acceptance. Release/main/U1/ABI holds
remain in place. The resource owner runs this foreground case serially only
inside the separately admitted disposable Linux VM, after source readback.

The three original additive files are `scripts/native-tcp-server-matrix.py`,
its artifact control file, and this document, first frozen unexecuted at
3bc9c2c586d092a32ca4dd6c4f449bb1271f9a2b. That source stays replayable and
was superseded before execution for the pending-response authority correction.
The 6334 source successor updated only the runner source binding and this doc.
A separate source successor under run 8ea6d20d-d9f1-4700-9973-efdca144151b
corrects directional ARP producer correspondence and adds one literal control.
All other TCP, native output, source, bounds and cleanup predicates stay unchanged.
The core, consumer, build script,
manifests, pins, lockfile and old runners remain byte-identical to the frozen
product revision. The independent Linux peer's single-connect correction is
described below; it is not an input to the native executable build.
The kernel input is the unchanged reviewed reason-log
successor ed6a15ea7c7c999422e1e294e139b6119619b06c, tree
5c3834dcdb8cf393c86bc0e436ae62c7cda67af5. No new dependency is introduced.

## Concrete input and build correspondence

The resource owner retains the clean build-source identities, complete build
command vectors, hashed build logs and pinned toolchain receipt. Before building,
create exact source replay archives with `git archive --format=tar REVISION`.
The platform archive SHA-256 is
75887cfefbf637a1806d912a5a3f703d8a638fb4bb13abc0382872f2f255dd9a;
the ed6 kernel archive SHA-256 is
568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e.
These are canonical uncompressed Git archives, not directory snapshots that
silently include compiler output. Source-only production computed their hashes
as streams without retaining another archive or running a compiler.

Build the two frozen consumers with `scripts/build-native-tcp-server.sh`, then
build the ed6 dedicated kernel using `EXTERNAL_USER_ELF` set to the exact
`tcp-server-service-probe.elf`. Preserve the original source files and build
logs. The runner requires a JSON receipt with schema
`absd-native-tcp-server-build/1` and these fields:

```json
{
  "schema": "absd-native-tcp-server-build/1",
  "platform": {
    "revision": "2b2f882ce486ed85ba32b21e039e4521c96e2c63",
    "tree": "699e237c94e00dec19266ec1fb8c8a02d165e412",
    "clean": true,
    "archive": {"path": "/absolute/platform.tar", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  },
  "kernel": {
    "revision": "ed6a15ea7c7c999422e1e294e139b6119619b06c",
    "tree": "5c3834dcdb8cf393c86bc0e436ae62c7cda67af5",
    "clean": true,
    "archive": {"path": "/absolute/kernel.tar", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  },
  "commands": [["sh", "scripts/build-native-tcp-server.sh"], ["make", "EXTERNAL_USER_ELF=/absolute/parent.elf", "durable-iso"]],
  "logs": [{"path": "/absolute/build.log", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}],
  "toolchain_receipt": {"path": "/absolute/toolchain.json", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
  "outputs": {
    "child": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
    "parent": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
    "kernel": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  }
}
```

This example is deliberately incomplete and cannot pass. Use actual commands,
sizes, hashes and custody paths from the serial build. The runner reads each
input once with a bound; the exact buffers define identities and retained
copies. It validates the reviewed archive hashes, build receipt/output hashes,
unique exact child containment in parent, and unique exact parent containment
in kernel. The same kernel buffer is staged into the ISO and must occur there
exactly once. Log and toolchain bytes are read, rehashed and retained too.
The receipt is the build owner's attestation of source/command consumption;
containment is direct byte evidence. Neither establishes compiler correctness
or proves the source of arbitrary supplied binaries without the build record.

The eventual resource-owner commands are:

```sh
python3 -B scripts/native-tcp-server-matrix-test.py
python3 -B scripts/native-tcp-server-cleanup-test.py
sudo python3 -B scripts/native-tcp-server-matrix.py FRESH_WORK \
  --child-elf /absolute/tcp-server-echo.elf \
  --elf /absolute/tcp-server-service-probe.elf \
  --kernel-elf /absolute/ed6-dedicated-kernel.elf \
  --build-receipt /absolute/build-receipt.json --timeout 120
```

Nothing in this source task executes those commands. A missing input, missing
predicate or cleanup failure is FAIL, never an implicit passing control.

## Independent peer and complete capture predicates

The runner creates a fresh named namespace and one TAP with Linux address
192.0.2.1/24, a fixed private fixture MAC and verified MTU 1500. IPv6 is disabled
in this IPv4-only namespace before creating the TAP. QEMU uses TCG, one CPU,
max/GenuineIntel/RDRAND and the fixed guest MAC. The raw QEMU capture is retained
unmodified. No synthetic readiness packet, capture rewrite, NIC counter reset,
readiness-based counter deduction or packet/SYN/MSS mutation is used.

The trusted parent emits LISTEN READY only after its channel processed LISTEN
and the sole socket exists. Only after observing that marker does the runner
launch a normal Linux AF_INET client bound to port 42031. Connect must time out
without data; the capture must contain its SYN and no server response or other
progress for that tuple. Then the unchanged independent Linux peer binds 42030,
connects, sends 3072 deterministic bytes, half-closes, checks every echoed byte,
observes EOF and exits normally. The serialized launch order and whole-capture
predicate require the refused SYN before the first authorized SYN; no eligible
SYN may precede it. The marker is a polled serial observation, not a clock
synchronization or hardware exclusion claim. Counter equality is unnecessary:
all four refusal/missed/TX-error counters must be zero over the complete boot.

The first native run `ec9cbda7` failed this strict capture check: the peer's
300 ms application connect/rebind loop abandoned an attempt, and Linux sent
a reset for its delayed SYN-ACK before the later connection completed. That
run remains FAIL. Its peer-only source successor makes one connect call after
LISTEN readiness, allowing four seconds for that handshake within one eight
second total peer budget. It performs no userspace reconnect; ordinary kernel
SYN retransmissions keep the same sequence identity. Product deadlines, exact
ELFs, source/packet predicates and the no-reset criterion remain unchanged.

Every captured frame must classify as exact peer ARP, an incoming wrong-port
SYN, or the exact authorized TCP tuple. The census checks Ethernet/IP tuples,
IPv4/TCP lengths, checksums, no fragments/options/extra protocols, bounded known
TCP options and MSS 1460 for both SYN directions on Ethernet1500. It reconstructs
3072 exact application bytes each way with consistent retransmissions, no
sequence gaps, ACKs bounded by already captured peer sequence space, peer FIN
before server FIN, and captured acknowledgement of both FINs. Both directions
need multiple data segments. Unknown peers, tuples, data, resets, malformed
frames or omitted capture records fail. The Linux socket result separately
requires the exact tuple/digest, write half-close and receive EOF.

Guest ARP requests require broadcast Ethernet destination and broadcast target
hardware bytes, as emitted by pinned smoltcp. Incoming Linux requests require
zero target hardware bytes and either broadcast or exact guest Ethernet
destination. Replies retain exact source/target IP and hardware tuples. A
literal control uses the unchanged 60-byte frame 12 from sealed native DHCP
run 46771e55-9091-4c55-8abd-cf98b1fc3173, capture SHA-256
fc2c88865999ee230df09a026dc3405670f3fdc1d9d164f1a726fd76aefd5fc0,
frame SHA-256 161373db3a1188391be4fa2f50c61e581f527a762a8941469636cc3515df9e2f.
Its producer, guest IP/MAC and peer IP match this profile; that request has no
peer MAC field. The pinned engine constructs the broadcast target hardware in
`smoltcp-0.14.0/src/iface/interface/mod.rs:1152`. Directional target/destination
substitutions must fail. This producer correspondence is existing DHCP packet
evidence, not TCP interoperability or a retroactive server execution verdict.

Native output requires exact ordered grant/listen/child/done markers, successful
child and parent accounting/exit, zero retained resources and positive traffic.
The wrong-port wire refusal is distinct from the child's actual framed wrong
peer denial and absent-NIC check. Authored host core boundary tests and native
negative cases other than that one source-port case remain explicitly UNRUN.
This is not a general listener, backlog, routed-path, clock or live SSH proof.

## Bounds, cleanup and custody

The whole guest/client phase has one 10..180-second host deadline. Every regular
file produced by QEMU or clients is capped at 2 MiB with RLIMIT_FSIZE; logical
serial/log limits remain 8 MiB and capture 2 MiB/256 complete frames. Input ELFs
and replay archives are bounded 64 MiB each, ISO 128 MiB, disk 2 MiB. The resource
owner must admit aggregate temporary storage separately; an upper estimate is
1 GiB worst-case file allocation including exact retained copies, two source
archives, at most eight build logs, ISO and producer file caps. The owner
measures actual inputs and admits the resulting aggregate before launching.
The 32 MiB source allowance does not admit that runtime allocation by itself.

The ISO builder and each long-lived process own a fresh session/process group.
The ISO builder has a 60-second bound and a 128 MiB file cap, with its log
checked against 8 MiB before success. Both
normal and failure paths terminate/wait exact owned groups, verify no group
remains, require the namespace have no processes, delete it and verify absence.
Cleanup addresses the original process group even if its leader has exited:
TERM is followed by a bounded group-absence wait and KILL if members remain.
Namespace creation is recorded as attempted before its control call, after an
initial exact-name absence check. Cleanup reconciles that name even if add
times out after mutation; it never deletes a pre-existing name without an
owned creation attempt. Unknown state, live namespace processes or residual
groups/namespaces fail cleanup. The original interruption remains a failed
run even when cleanup subsequently establishes resource absence.
This short foreground run assumes continued ownership of the original PGIDs
and that descendants stay in their owned session/group. It is not a general
PID-reuse or daemon-reparenting proof. Unknown control/identity state requires
resource-owner reconciliation instead of a cleanup success claim.
Cleanup failure overrides any pending PASS. Fresh RESULT, LAUNCH,
LISTEN-OBSERVED and LOCAL-CLEANUP records keep execution distinct from source
readiness. TERM/INT enters cleanup; SIGKILL/host loss cannot guarantee cleanup
and must be reconciled by the resource owner from LAUNCH before retrying.
This foreground case is not an unattended producer or supervisor-loss service.

Root is the accountable storage owner. Retain exact sources, replay archives,
ELFs/ISO, capture and minimal records until independent review/replay custody
ends. Retire reproducible staging/disk/log copies only after the named consumer
dependency ends and ownership checks; review 2026-10-17. No VM, key, namespace,
compiler output or capture is created by source production.

## Formalization consideration

The proposition is limited: observed LISTEN precedes the controlled wrong-port
attempt, wrong-port traffic cannot consume the slot, and one authorized finite
flow corresponds across native result, Linux result and a fully explained
capture. Source/replay hashes constrain substitution; the trusted build owner,
capture completeness, Linux kernel and parser correspondence are assumptions.
Fourteen pure artifact methods cover directional ARP correspondence,
missing/reordered refusal, wrong tuple,
checksum/data substitution, sequence/ACK gaps, FIN/EOF/MSS/reset omissions,
native counters/accounting and exact embed/source substitutions. They are
authored and UNEXECUTED. Two separate cleanup substitution controls preserve
the exited-leader/group case and namespace mutation followed by timeout,
including unknown/live residual refusal. They replace OS controls only within
those tests and create no real signal/namespace effect. The original fourteen
artifact methods remain unchanged. Practical finite controls and explicit prose are
proportional; no proof of arbitrary TCP, compiler trust, hardware ownership or
post-effect rollback is claimed. S2 root owns the decision and independent
acceptance remains external to this runner.
