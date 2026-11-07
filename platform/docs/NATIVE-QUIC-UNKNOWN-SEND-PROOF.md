# Native QUIC completion loss: Q20

This is an explicit bounded development proof for the existing current Q20
consumer in `quic/CASES.json`, `quic_service_probe` and `quic_echo`. It follows
the actual queue-exhaustion development result on base
`14b6569ca965d8184b1ff07e6d93255a977213f5`. The initial proof-only source
`852768c0b0b0942d3bd02fe244aaaa4fd699c126` left native Rust unchanged.
Its actual occurrence below failed. The prospective successor additionally
settles the Q20 private parent before constructing a grant. The transport,
CASES contract, protocol dependencies, authority and packet budgets remain
unchanged. Execution of this successor is UNRUN until a
receipt binds the exact source and raw results. Earlier results are unchanged.

Q19 can retry a datagram that is known not to have been queued. Q20 loses a
completion after the service has accepted the SEND. That uncertainty fences
the owned client channel; it does not authorize retrying the operation.
`send_accepted=0` counts replies observed by the child. It does not assert
that zero datagrams were queued or reached the wire.

## Existing native fixture

The service's current `FixturePipe` suppresses exactly one complete successful
14-byte framed SEND reply, acknowledging that write to `Session` while
withholding it from the child. The service has already accepted the SEND.
The child's existing 250ms transaction bound produces `Unknown(-110)` and
drops the owned pipe. The selected original operation deadline and 15-second
grant remain unchanged. Source-bound service records distinguish request,
suppressed completion, client fence and child exit. They do not introduce a
new object ABI or transfer protocol.

The checker requires one 1200-byte SEND request, one suppressed successful
reply, one engine transmit, zero child acknowledged sends/bytes, zero known
Exhausted responses, no retry, no accepted close, no successful RECEIVE and
no application bytes or authentication. It checks the original grant and
request/suppression/fence/end order, normal child reap, and restored process,
handle, pipe and cell counts. Frames are observed separately.

## Independent Linux observation

Only `--profile q20-unknown-send-development`, canonical Q20 and port 7819
select this proof. The Linux UDP peer parses and retains the first full
QUICv1 Initial before constructing a QUIC connection. Its explicit
`q20-one-initial-sink-v1` policy has no peer engine, certificate selection,
response or retransmission timer. A second client datagram, including an
identical retry, fails the fixture. The whole Ethernet capture must contain
exactly one checksum-valid 1200-byte QUICv1 Initial on the exact tuple, plus
only the existing permitted ARP traffic. Q20 requires zero peer datagrams. The separately admitted Q07 silent
profile retains its existing zero-peer rule; other capture profiles retain
their existing direction and packet bounds.

This deliberately establishes a possible external effect before the child
fences. An absent Initial fails as NOT_ESTABLISHED. The sink does not claim
to authenticate or decrypt that datagram. A same-source, same-runner,
same-peer-closure, same-manifest, same-PKI Linux Q01 echo/FIN control is the
explicit prerequisite. Linux cannot reproduce native IPC completion loss;
`--controls` for Q20 selects and labels the actual Q01 echo calibration,
with Q20 retained as the requested profile. Explicit `--case Q20 --controls`
and direct Linux Q20 control refuse. Q01 retains its ordinary echo profile. Root and PKI identities remain bound to the
client build and Q01 prerequisite, while Q20 explicitly selects no peer
certificate.

## Execution and evidence

Use a dedicated occurrence identity and the existing isolated finite VM
resource procedure. Retain exact source/tree, compiler/dependency identity,
fresh fixture trust, child and parent build receipts, current kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b` and its exact served-build
wrapper/feature receipt, actual boot bytes, raw serial, complete PCAP,
peer events, original unit identity/terminal and resource restoration.
Do not start a second mutable target while another lane owns the VM.

Run the old 98 artifact controls unchanged, the 16 new controls in
`scripts/test-native-quic-unknown-send.py`, and the existing native transport
host suite. New controls use synthetic records and a literal Ethernet vector;
their results are not native protocol evidence. Native Q01 and Q08 remain
useful same-source positive and authentication controls alongside Q20.
Public-input and source snapshots must remain stable. Exact results, counts
and any carried versus repeated build/test attribution belong in receipts.

After custody, the creator retires exact fixture keys, private DER, compiler
targets and VM scratch after consumer checks. Preserve minimal source,
replay inputs and raw result dependencies through integration disposition;
the creating owner records a bounded review date. Default SSH, release and
U1 acceptance holds remain in force. This profile does not satisfy the full
17-Linux-control or 30+1-native campaign, and does not change its verdicts.

## Formalization and kernel evolution consideration

The proposition is that loss of a SEND completion fences subsequent authority
without reconstructing certainty about the already possible first effect.
Scope is the current single owner/session, bounded native transaction and
deterministic completion-loss fixture. Existing transport tests cover pipe
drop and refusal of a second request. Sixteen new finite controls and actual
raw service/wire evidence are proportionate to this proof-only addition; a
separate model duplicating this straight-line fencing is not chosen.

Logical service identity does not revive the fenced handle. No replacement
state, schema, authority rebind or in-kernel module is added. Future generation
replacement must quiesce/fence old operations, reconstruct authority under an
explicit rule, validate the successor and refuse unsupported transfer. It
cannot roll back an externally visible datagram or infer absence of effect
from this child's zero acknowledgements. Hardware exclusion, live transfer,
post-effect rollback and full QUIC conformance remain outside this proof.
S2 owns the bounded proof decision; the integration steward independently
decides selection and acceptance from the exact evidence.

## Prospective pre-grant readiness correction

Original run `a9a91b84-5b26-49dc-9e9d-1b48f1631d93` on source 852 correctly
remains FAIL. Native Q01/Q08 and 113 artifact controls/20 host tests passed.
Q20 produced `Unknown(-110)`, one SEND, one suppressed successful reply and
no retry. Its complete PCAP contained only an ARP request and Linux reply,
while native NIC counters reported zero received frames. No UDP Initial or
sink receipt established the required wire effect. Logical queue acceptance
and the lost completion were insufficient to claim that effect.

The successor carries the existing IPv6 fixture's bounded 1100ms pre-grant
settling loop into Q20 only. It checks an available/up NIC reading and
rejects clock rewind, overflow or reaching 3000ms. No Stack/network poll,
grant or child operation runs during setup. The actual setup marker is
mandatory and must precede grant construction; its explicit continuous-VM
assumption is retained. It is an experimental settling condition, not proof
that a captured ARP reply will reach hardware. The strict one-Initial Linux
receipt/full-capture predicate is unchanged. Send completion remains bounded
at 250ms, operation at 10 seconds and grant at 15 seconds from their original
construction, after setup. Q01/Q08 and all other cases retain their parent
behavior.

The synthetic positive constructor moves its absolute clock origin by 2000ms
so setup fits before the grant. One existing negative method updates the same
three clock mutations; assertions and refusal purposes are unchanged. A 16th
control requires bounded continuous pre-grant setup. All original 98 controls
remain byte-identical. The parent must be rebuilt on the successor source;
source/child receipt reuse requires exact correspondence, never silently
relabels source 852 outputs. Independent practical source review, finite
controls and the retained counterexample are sufficient for this fixture
correction; there is no transport or authority reconstruction mechanism.

## Current S2 continuation

The current carry starts from `de3c5b89a972c2b5b17198670f938b40dce7973a`,
which includes the delivered Q15 selectors and Q05 post-handshake preparation.
It carries `852768c0` and `03e90287`; those historical source and runtime
identities retain their original dispositions. This is a fresh source
continuation, not resumption of a prior producer or reuse of its credentials.

The merge preserves the newer IPv6 and case tables. Native Q20 alone uses
the same-source Linux Q01 prerequisite. Every other selected case keeps its
existing prerequisite, including IPv6 Q17's IPv6 Q01 control. Q20 refuses a
wrong local port or IPv6 selection. Its pre-grant setup block is copied
exactly from the reviewed correction; the existing IPv6 setup block is
unchanged. The peer's one-Initial sink and strict unknown-completion
predicate retain their reviewed source bodies. The native client, engine,
CASES, locks and dependencies are unchanged from the current base.

The current source check ran 403 finite methods: the existing source and
QUIC suites, PIN controls, the sixteen completion-loss controls, and served
kernel/RAM controls. These are host construction/artifact controls, not Rust
host tests or native protocol evidence. A disposable invocation wrapper
first passed its script pathname to unittest as a selector and executed no
product controls; its failed diagnostic receipt is retained separately.
The corrected wrapper resets argv before running the unchanged suites.
Expanded negative selections cover Q20's wrong port and IPv6 refusal.

The carry's formalization consideration is correspondence: the existing
case/family routes must retain their prior acceptance conditions, while Q20
requires one observed first effect and forbids replay after uncertain
completion. Source-body comparison, finite refusal controls and exact fresh
wire/lifecycle evidence are sufficient for this bounded change. No new
state-transfer schema or authority mechanism is introduced. Source/oracle
and raw acceptance remain independent; current native execution is UNRUN.
