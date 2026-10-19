# Native IPv4 DNS stub resolver

This is issue #13's initial UDP-only resolver tranche toward a mature network
stack for common Internet protocols. `absd_net::dns` owns the ABSD interface;
smoltcp remains the IPv4/TCP/UDP engine. No new kernel object or syscall is used.
It does not install a resolver in the operator image or add SSH hostname lookup.

## Authority and use

The trusted NIC holder issues one `datagram::Grant` for one configured IPv4
resolver address and port (normally 53), with an explicit local port >=1024.
It constructs a native pipe channel as documented in NATIVE-UDP.md. The consumer
owns only that channel; `dns::Datagram<P>` owns the pipe and the peer address.
Client-provided configuration cannot expand the owner's grant. No filesystem,
network discovery, environment setting, or Unix resolver configuration supplies
ambient authority. Resolver configuration is an explicit construction input.

`Resolver::new(transport, initial_id).lookup(hostname)` returns an `Answer`
containing up to eight IPv4 addresses and the number of CNAME transitions, or a
typed `Error`. Addresses are deduplicated, retaining answer-record order. Only
IN A records at the requested name or its validated CNAME chain are used;
authority/additional records do not supply addresses. Record order within the
answer section is immaterial to chain traversal. Contradictory CNAME targets,
or CNAME plus A at the same owner, are refused. CNAME-only replies cause another
query to the same configured server. This stub does not chase referrals.

Input names use ASCII letters, digits, hyphen and underscore in nonempty labels
of 1..63 bytes, case-insensitive, with an optional single trailing dot. Maximum
encoded name length is 255 bytes including the root byte. Root-only names,
binary labels, IDNA conversion, escapes and search suffixes are unsupported.
Names decoded from replies use the same restricted alphabet, including owner
names in every section; some otherwise legitimate replies are refused. Compression
pointers must point backward into the DNS message past its header, with bounded
decoding and expanded lengths. Malformed matching messages are refused.

The native `dns_client` diagnostic accepts a hostname in its startup arguments;
its bootstrap stdin supplies mode plus resolver IPv4/port (seven bytes), then
stdin/stdout become the granted datagram channel. Stderr reports the hostname,
addresses or precise error through a separate result pipe. It has no NIC or
spawn right. `--suite` is the development fixture workload. The service probe
uses the established startup record for separate stderr and existing raw
`spawn_image` with narrowed read/write pipe handles; it is not a new launcher ABI.

## Bounds and outcomes

One lookup is active per resolver instance/channel. Concurrency is limited by
the owner's maximum eight UDP endpoints, each retaining the UDP contract's four
packets per RX/TX queue. The resolver reads at most 1472 bytes per datagram,
parses at most 64 resource records, follows at most eight CNAME transitions,
returns at most eight distinct addresses and retains at most nine names.
Oversized address/record/chain sets return `Exhausted` without partial success.
No EDNS option is sent; ordinary queries are compatible with the original
512-byte DNS UDP contract. A matching TC response returns `Truncated`, including
when it contains apparently useful records. TCP fallback is explicitly deferred.
An oversized datagram not observable through the bounded UDP engine can appear
as a timeout; `TooLarge` is used only when the transport reports it.

Each lookup has one absolute 3000 ms monotonic deadline across all CNAME queries.
Each queried name is sent at most twice, with a 750 ms retry interval. At most
18 datagrams can be queued for a lookup (nine queried names, two each); CNAMEs
included in a reply usually reduce that number. Empty queues pause five ms.
A lookup timeout permanently retires its resolver instance. Drop it and acquire
a fresh owner-issued channel, even when the last RPC happened to complete:
near the deadline a partially completed stream transaction cannot be resumed.
An RPC timeout at the overall lookup deadline reports `Timeout`; an earlier
RPC timeout remains a distinct channel error. Neither resends an uncertain SEND.
A locally full TX queue is retried within the same deadline; interrupted SEND
pipe transactions invalidate the channel and never cause a SEND retry. The UDP
engine still distinguishes local queueing from remote receipt.

Replies must match the exact resolver peer, transaction ID, IN A question and
normalized full name. Unrelated messages are ignored within the original
deadline. Transaction IDs visit each 16-bit value at most once in an instance,
including failed lookups; exhaustion refuses further queries. `initial_id` is
caller-selected by `Resolver::new`, not an entropy guarantee. Native UDP and
paired TCP/DNS diagnostics use `Resolver::with_entropy` with the existing
package `getrandom` provider, configured for RDRAND on ABSD. Failure ends the
diagnostic explicitly before a DNS query, with no static or clock fallback.
The initial seed is only 16 bits and later IDs are sequential, so it does not
authenticate DNS/ICMP or eliminate predictable quotations. Other native
consumers must select an appropriate existing entropy provider through
their authorized owner. A matching fabricated or corrupted reply can fail a lookup. A transport must remain bound to one
resolver instance for its lifetime; constructing another instance around the
same channel would violate this lifetime contract. These checks are response
correlation, not authentication or a complete DNS integrity mechanism.

Errors distinguish invalid names, malformed responses, NXDOMAIN, no address,
REFUSED, SERVFAIL, other DNS response codes, truncation, oversized responses,
CNAME loops, resource exhaustion, timeout, pipe failure and UDP lifecycle refusal.
An absent or unresponsive server times out. No ICMP-unreachable distinction is
claimed because this UDP interface does not report it. There is no cache,
positive or negative TTL continuity, or promise to select a usable destination
from a syntactically valid A record. Returned addresses confer no connection
rights.

## Failure and replacement

The logical resolver is its configured peer plus authorized channel identity;
the implementation instance and its transaction sequence are one generation.
EOF, pipe interruption or UDP carrier/device/configuration fencing does not
revive the old endpoint. Reconfiguration/restart needs a fresh owner-issued
channel; pending lookups fail and are explicitly resubmitted by the caller. A timeout
never allows another lookup through the same resolver instance.
The owner must avoid reusing local port/peer pairs while delayed datagrams can
matter: no DNS transaction ID or local endpoint epoch distinguishes a delayed
reply across a fresh generation if the wire tuple and ID/question are reused.

No replacement state is exported: all in-flight state is discarded. A future
transfer ABI must version configuration identity, pending request identity,
clock epoch/deadlines, used IDs and authority reconstruction rules, and refuse
conversion without those preconditions. Native Rust layout is not a transfer
schema. Quiescence requires stopping request admission, fencing channels and
settling or refusing lookups. Successor validation and commit remain outside
the component; rollback cannot recall queries already emitted or revive old
handles. Kernel/NIC/DMA handover, state transfer and L3/L4 live replacement are
not implemented by this tranche.

## Build and qualification

```
cargo +1.95.0 test --manifest-path net/Cargo.toml \
  --target x86_64-unknown-linux-gnu --target-dir .dns-host --locked --offline
scripts/build-native-dns.sh
python3 scripts/native-dns-matrix.py WORK --linux
python3 scripts/native-dns-matrix.py WORK --kernel ISOLATED_KERNEL --elf dns-service-probe.elf
```

Apply the steward's current CPU/job/load/storage limits to builds. The last
command needs an exact guest admission and a private kernel checkout at the
pinned revision; it never acquires the slot itself. Existing net-matrix helpers
remain unchanged. Linux `dig` checks seven fixture cases over UDP and TCP; this establishes
fixture behavior, not native resolver behavior;
the native workload verifies explicit UDP TC refusal with no TCP fallback, two concurrent
suite consumers plus a fresh diagnostic consumer after timeout, malformed/negative replies, mismatched IDs/questions, delayed old
replies, retry and absent-server timeout, partial frames, survival of a client killed during its lookup window and
simultaneous ordinary TCP echo. Success requires kernel zero cleanup accounting.
Host transport tests additionally check interruption and exact-peer refusal;
existing UDP tests cover endpoint exhaustion, link fencing and fresh grants.

Implementation derives from RFC 1035 sections 2.3, 4.1 and 7.3 and RFC 2181
section 10.1, not third-party implementation source:
https://www.rfc-editor.org/rfc/rfc1035.html
https://www.rfc-editor.org/rfc/rfc2181.html

Exact source, runner, build, executable and evidence identities live in the S2
DNS lane receipt. Independent review and steward integration disposition are
separate from a producer's completion notice and host or guest test results.

## Formalization consideration

Owner: S2 producer for implementation claims; independent reviewer/steward for
acceptance. Proposition: within one resolver/transport lifetime, no transaction
ID repeats; replies cannot widen peer authority; lookup processing and state
are bounded by the declared constants under the Transport clock/deadline
contract. The ID allocation space is exhaustively checked for all 65536 values;
parser fixtures and all single-byte substitutions of an independent baseline
terminate without panic; their individual semantic outcomes are not asserted. Existing UDP lifecycle and narrowed-pipe tests
supply the authority correspondence. Practical tests and this bounded contract
are sufficient for this tranche; they do not prove all possible DNS messages,
authentication, clock behavior outside the stated contract, availability under
queue exhaustion, or cross-generation wire identity. A future transfer schema
would need a separate bounded state-transition model. Source/result identities
and observed counterexamples are recorded in the run's formalization receipt.

## Demonstrated development slice, 2026-10-15

Qualified executable source is `2fd9ae8459fee6091a969def0bb277db580abe06`
with unchanged kernel `f8184cae7dd6a097f47331fb763c2f5fdae770cc`. The final
driver revision is `1d508361dfe66ac217cd5f2aeb1fcf7aae304d5a`; its only
delta is the diagnostic's query-count check against the declared two-send bound.
Client SHA256 is
`790e35081931e3f896d5485c77e7d14cce5127b5853b24e0f6d6fcf7dc927a7f`;
service SHA256 is
`1e2311cf860e79b21b99dda8a996eb585f37d0ccc4c616f8483e8e209ac414cb`.
The final run is `d78d15f4-0328-42ca-94a0-f52dbfa92bdc` under the shared
S2 DNS registry. Native source/build/runner/serial/result identities and
independent review pointers are in its handoff receipt.

Host results: 18 DNS tests plus 37 pre-existing network tests passed; 17
existing SSH tests passed. Seven Linux dig fixture controls passed over UDP
and TCP. The final default-TCG QEMU guest (128 MiB, one vCPU, e1000) produced
29 expected typed lookup results across two concurrent suite clients and a
fresh diagnostic client. Both timeout instances refused reuse. A fresh grant
resolved through a delayed old reply. UDP TC refusal opened no TCP DNS
connection; a separate conventional Linux TCP peer echoed 43 bytes. Partial
channel expiry and a killed child's terminal kind were checked. The original
serial records `DURABLE status=0 frames=0 processes=0 cells=0 pipes=0`,
`DURABLE WORKLOAD OK` and `ABSD BOOT OK`; the unchanged boot helper required
QEMU debug-exit status 3. This is controlled Linux-fixture evidence, not
real-resolver, full SSH guest regression, physical NIC or release qualification.

Three preceding failed runs remain failed: `c252af61` could not expose the
consumer's error because the diagnostic returned before printing its buffer;
`63d5acde` exposed `Channel(-110)` on DNS deadline expiry, repaired by typed
Timeout and resolver retirement; `f3de2c44` completed the native workload with
zero accounting but its driver incorrectly required exactly one query when
the contract allowed a second identical transmission. The steward reviewed
that diagnostic correction and admitted a new run; no historical verdict was
rewritten. All original records remain linked from the handoff.

The source boundary received independent read-only review
`GUEST_OK_WITH_NOTES`; the steward reviewed each subsequent delta and admitted
exact guest identities. Producer completion, independent evidence inspection
and selective integration acceptance are separate records. No main, push,
publication, release or U1 hold is advanced by this development result.

Follow-ons remain on the canonical ABSD Program backlog: DNS TCP fallback and
broader response handling in issue #13, protocol-engine direction in #14, and
owner-requested native QUIC after sufficient TCP maturity in #26.
