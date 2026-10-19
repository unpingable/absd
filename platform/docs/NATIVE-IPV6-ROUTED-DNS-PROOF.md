# One static routed UDP DNS proof

The prospective runner `scripts/native-ipv6-route-matrix.py` compiles nothing.
It consumes runtime `84c92a928b4957265f2888e8de75bc4b03bd7109`, tree
`62723f5a614976cd5a7927b5a87811fc058e570e`, canonical tar 22,630,400 bytes,
SHA256 `2aa6bf01fecee0a68379858abb5d5db9bd5c816c37a48743dccd7f1fb5581994`.
The kernel is lane ed6a15ea7c7c999422e1e294e139b6119619b06c, tree
5c3834dcdb8cf393c86bc0e436ae62c7cda67af5, tar 11,417,600 bytes, SHA256
568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e.
The proof tip is separate from runtime. These sources have no native result at
this source freeze. The accepted ddb3 host suites and old DAD/Echo results
retain their original source attribution.

One router namespace owns a TAP at fd00:ab5d:1::2/64 and veth at
fd00:ab5d:2::1/64. A second namespace owns the peer veth at fd00:ab5d:2::9/64,
an explicit return route, and an AF_INET6 UDP socket on 42010. Linux forwarding,
ND, IPv6 and UDP implement the independent network side. The application only
returns controlled DNS A/AAAA answers. No public server, user packet forwarder,
raw injection or private PKI is involved. Addresses are static with nodad and
addrgenmode none. Forwarding is explicit, RA/autoconfiguration are disabled,
normal MLD is retained, and segmentation/checksum offloads are disabled for
capture correspondence. The router egress also has the single explicit
link-local address fe80::203/64, installed with nodad. Linux v6.8
[`ndisc_solicit` and `ndisc_send_ns`](https://github.com/torvalds/linux/blob/v6.8/net/ipv6/ndisc.c#L612-L629)
require a local link-local source when a forwarded packet's source is not local
to the egress interface (see also lines 692–715). Disabling address generation
without supplying that source prevents Linux egress NS. Only this named
link-local's NS and matching peer NA are explained on the peer link; reverse
peer resolution of the configured ULA gateway keeps its exact original tuple.
This is Linux fixture configuration, with no new guest address or authority.
Address and link JSON rows are joined by exact positive
ifindex and ifname;
MAC, MTU and UP flags come from `ip -j link show`, since authentic
`ip -j -6 addr show` omits MAC. This corrects an unexecuted pre-QEMU source
blocker in c02; its synthetic constructor had invented the address MAC field.
Original c02 21-method PASS remains its actual result, without native claims.
Each actual setting and installed Linux identity is retained; failure to
establish it fails the case.

The guest sends from fd00:ab5d:1::15:7002 to the exact off-link peer. Every
complete IPv6 UDP packet must appear on both links, with identical bytes except
for one hop-limit decrement. Every captured frame must be classified by its
exact link MACs and tuple, valid checksum/length, supported ND envelope or
bounded normal MLDv2 envelope. Real NS then NA must precede the first query on
each link. Socket records bind complete question bytes/ID/type/source and exact
controlled answers to both capture censuses and their multiplicity. Missing,
extra, truncated, malformed, unknown or out-of-order traffic refuses PASS.
Neither capture timestamps nor the RX preparation boot interval establishes a
host/guest clock mapping or hardware readiness theorem.

QEMU runs one CPU, 256 MiB, TCG, max,vendor=GenuineIntel,+rdrand, e1000. Its
expected success exit is 3. Exact source/build receipt fields, original empty
input/expected buffers, compiler/tool logs, child inside parent inside kernel,
and actual ISO critical file extents must match. A selected QEMU pathname may
be a launcher; its hash does not identify a distro executable behind it.
The raw serial must bind all literal control/output lines, native child and
parent success, durable outcome, available terminal zeros, exact four-counter
before/after equality and endpoint retirement. Physical frames are observed,
not required to return to an allocator high-water baseline. The parent's
pre-poll RX preparation must report at least 1,100 boot milliseconds, under the
original 12 s invocation and continuous VM assumption.

The parent's no-route denial, nine malformed Session requests, three direct
peer refusals, queue/slot ceilings and stale checks execute in ABSD before any
queued fixture data can reach the NIC. Partial-prefix EOF/expiry use real
kernel pipes. The child's three wrong-peer/scope/port denials are actual framed
pipe transactions; nic=0 follows its construction and actual code checks.
These controls do not establish malformed IPv6/ND wire execution, killed-child
interruption or device fault injection. Such cases remain UNRUN, as do routed
TCP, PMTU, automatic route authority and DAD for this static construction.

The unchanged accepted accounting helper is loaded from its hash-bound buffer;
its globals/source/classifier are not rewritten. The new explicit two-link
classifier handles the route topology. The ed6 first-four diagnostic profile
requires exact logged refusal cardinality at rx_refused <=4, captured compatible
MLD destinations, no protocol peer refusal, no unexplained frame and zero
rx_missed/tx_refused/tx_errors. Its readiness sidecar binds actual raw capture
prefixes without changing a packet. It does not synchronize boot-cumulative
counters, serial observation or DMA; exceeding the log budget is inconclusive
and refuses PASS. No old stricter case or historical verdict is rewritten.

All semantic setup/peer/launch/cleanup buffers are evaluated once and bound
through final seal. Terminal cleanup updates the same evaluated mapping
returned by run, so a later content mutation cannot sit beside an earlier
PASS. Owned namespace creation is marked before the mutating command. Each successful
creation immediately records dev+inode in a bound fact; topology and cleanup
require that same identity. Cleanup checks identity again after the empty-pid
observation, before deleting. A timed-out add with an unknown residual identity
or any replacement is cleanup FAIL and is retained for provider reconciliation;
actual absence can clear uncertainty without deletion. These are observations
on the exclusive local fixture, not an atomic namespace replacement theorem.
This corrects a second unexecuted c02 source gap; historical results stay intact. Each owned process
group is stopped even if its leader exited, and residual/unknown/forced cleanup
fails. Source/ELFs/raw capture/serial/ISO/results remain in the unique owned case
directory for full custody; only after handoff and dependency checks may the
creator retire reproducible substrate. Root is storage owner; keys/provider
lifecycle belongs to the separately named disposable resource owner.

Example after exact native build and a separately recorded resource occurrence:

```sh
python3 -B scripts/native-ipv6-route-matrix.py /owned/new-case \
  --run-id FRESH-UUID --kernel-elf /owned/absd-kernel \
  --elf /owned/ipv6-route-service-probe.elf \
  --client-elf /owned/ipv6-route-dns-client.elf \
  --build-receipt /owned/ROUTE-BUILD.json --lease-end ABSOLUTE-UTC --timeout 150
```

The strict build schema is `absd-native-ipv6-route-build/1`: platform/kernel
revision/tree/clean/canonical-archive identity, commands including the existing
route build recipe and exact external-build/empty-input arguments, hashed
nonempty toolchain receipt/build logs, three exact output hashes and external
buffer paths/hashes. Existing first-party ELF/ISO/process-group/seal functions
are reused from the owned Echo proof. The unchanged DNS helper supplies the
pure codec and bounded Linux socket fixture; this is not QUIC source reuse.
Run all deterministic artifact controls with
`python3 -B scripts/native-ipv6-route-matrix-test.py -v`. Three standalone Rust
fixture methods and the original 21 Python methods passed at c02. The corrected
22-method artifact successor is initially UNRUN; it adds namespace replacement,
unknown-creation and absence controls. Their
later actual receipts are distinct from wire execution and independent review.

The formalization proposition is one immutable owner route plus current checked
endpoint authority, exact two-link effects and bounded refusal/retirement.
Practical literal vectors, meaningful substitution controls and exact source
review are proportionate, conditional on compiler, Linux/QEMU and filesystem
observations. No Rust layout is a replacement schema; no queued packet, handle
or observed first uncertain effect can be rolled back or grant revived. Live
kernel state/authority transfer, interrupted syscall effects and physical DMA
remain outside this proof. A future successor needs explicit state conversion,
authority reconstruction and external validation; these artifacts supply no
mechanism or automatic downgrade guarantee.

The first native occurrence 2f978778 remains FAIL: its guest capture contains
valid router NS/NA followed by two valid DNS UDP submissions to the router MAC,
while its peer capture has no frames and its Linux socket has no questions.
The installed namespace had no egress link-local address. The explicit address
above corrects this fixture source gap; it does not convert that old run into a
PASS or establish a later wire result. Runtime84, the peer application, engine,
kernel and build inputs are unchanged. The successor adds two artifact methods
for missing/substituted link-local setup and exact forward/reverse ND, for
24 authored methods; their execution and the new native replay are initially
UNRUN. Installed-kernel behavior, full two-link census and unchanged end-to-end
checks remain authoritative. Practical source correspondence and substitution
controls cover this finite fixture correction; no Linux forwarding theorem or
guest generation-transfer claim follows from it.

Occurrence 526cbe93 passed all 24 artifact methods, the 208/220 network
suites and four selected mutation controls. Its guest and Linux socket completed
both questions, with QEMU exit 3 and resource restoration. The overall strict
case nevertheless remains FAIL: tcpdump reported two captured packets, ten
received by filter and zero kernel drops, while the peer PCAP contained only
two earlier MLD reports. The eight later frames were unavailable to the proof.
The successor adds only `--immediate-mode` to tcpdump, retaining `-U`: the
[tcpdump 4.99.4 manual](https://github.com/the-tcpdump-group/tcpdump/blob/tcpdump-4.99.4/tcpdump.1.in#L483-L489)
distinguishes immediate capture input delivery from packet-buffered output
(lines 773–793). No wait, fabricated packet or missing-frame tolerance is added.
All strict predicates and 24 artifact method bodies are unchanged; a fresh
complete two-link native capture remains required and initially UNRUN. The
208/220 and mutation results retain their exact cf603 source attribution, and
the compiled native runtime remains 84/c108. This bounded capture configuration
change relies on the actual retained packet census, not on an input-delivery
or shutdown atomicity theorem.
