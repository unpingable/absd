# Private routed IPv6 HTTPS fixture

This source tranche composes the existing native TLS consumer with the explicit
IPv6 TCP route already demonstrated by the routed DNS/TCP fixture. It remains a
private three-case development fixture. Its Rust builds, 45 authored TLS test
methods, 44 artifact controls and native P01/P02/L07 cases are UNRUN at source
handoff. Existing on-link runners and their historical results retain their own
source attribution. No Internet readiness or campaign acceptance follows from
this document.

The compile-selected `on-link` profile remains the default. The explicit
`--ipv6-routed` builder option selects local `fd00:ab5d:1::15/64`, router
`fd00:ab5d:1::2`, peer `fd00:ab5d:2::9`, scope 1 and TCP port 4443. Unknown
profile names refuse. The NIC-owning parent first checks that an off-link stream
grant is denied without a route, installs the existing exact-peer route, and
then constructs the existing local-port-7401 stream grant and dedicated pipe
channel before the child's CONNECT. A profile describes construction; it grants
no authority. The child has no NIC or block authority. Wrong-port L07 still
requests 4444 against the grant for 4443 and must receive the exact denied reply
without a TCP connection on either link.

The TLS engine, configured root verifier, reference name `absd-fixture.test`,
TLS 1.3, disabled resumption/early data, public validation time and request bytes
are unchanged. The child retains its 10-second operation deadline, bounded by
the original 15-second grant expiry, within the parent's 20-second invocation.
The new profile does not change a socket ABI, dependency, SSH behavior or
release/U1 hold. Both selected actors must use the same product source, public
root, route profile and child executable. A routed service-only build requires
the sealed client build receipt; a child from the on-link profile refuses.

## Build inputs and receipt

Build only on the separately allocated disposable VM, using a clean checkout of
the sealed product revision. The proof checkout is separate. The native builder
uses the existing locked public dependencies, native Clang/LLVM flags and staged
std identity `c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c`
(2,251 files / 45,920,288 bytes). PKI creation and VM lifecycle belong to the
named runtime owner. No old private key is imported, and this runner creates no
keys. The public root DER belongs in the declared ignored
`fixtures/native-tls/pki` directory. Record public root/certificate fingerprints,
validation time, fixture-private key custody and a finite retirement condition
before creation. Retain only public certificates in normal evidence.

An example command shape, with absolute paths supplied by the runtime owner:

```sh
python3 scripts/build-native-tls-fixture.py --ipv6-routed --client-only \
  --stage /run-owned/ring-stage --cargo-home /run-owned/cargo \
  --receipt /run-owned/inputs/client-build.json
# Move only this declared generated output outside the product checkout.
mv https-ipv6-client.elf /run-owned/inputs/child.elf
ABSD_TLS_CASE=P01 ABSD_TLS_UNIX_SECONDS=VALIDATION_ANCHOR \
ABSD_TLS_CLIENT_ELF=/run-owned/inputs/child.elf \
ABSD_TLS_CLIENT_SHA256=SEALED_CHILD_SHA256 \
python3 scripts/build-native-tls-fixture.py --ipv6-routed --service-only \
  --client-receipt /run-owned/inputs/client-build.json \
  --stage /run-owned/ring-stage --cargo-home /run-owned/cargo \
  --receipt /run-owned/inputs/P01-service-build.json
mv https-ipv6-service-probe.elf /run-owned/inputs/P01-parent.elf
```

Also supply `ABSD_TLS_ROOT_DER` and `ABSD_TLS_ROOT_SHA256` for each command.
Each service selector gets its own receipt/output. The child is root-pinned and
may be reused for P01/P02/L07 with that exact receipt. Stage/install packages
before a producer launches. The canonical kernel external build uses this exact
parent with empty external input/expected files. Preserve actual command arrays,
raw logs, tool versions/hashes, archives/raw commits, actor receipts and output
hashes. Move and hash only declared generated ELF outputs before a literal
source-clean check; do not broadly whitelist source changes.

The prospective current-kernel pair is `38b4242f4b3e0b05ad13cc21aa0890c1fbe99074`
(tree `92ef86310444ff218bd00e9d6ea28f04294d0a13`). The product remains
`d1a6ee0b3ec14559804a0b03d4c9d59bdfd857c5`. Invoke the product
`scripts/served_kernel.py` wrapper for the kernel external build, preserving its
`frame-admission-v0` policy. Do not override or omit that feature to pair a
current platform with an older kernel. Prior `e70e2a42`/`ed6a15ea` source pins
remain a separate source-only historical record. This pairing is not live
replacement or hardware-transfer evidence.

The aggregate build receipt schema is
`absd-native-ipv6-routed-tls-build/1`. It has `case`, `tls_lock_sha256`, exact
`platform` and `kernel` objects (`revision`, `tree`, `clean`, `archive`), exact
`outputs` for child/parent/kernel, `external` input/expected/parent path and
hash objects, `commands`, `toolchain_receipt`, and one to eight `logs` digest
objects, plus `served_kernel_policy` containing `features: "frame-admission-v0"`
and the exact `scripts/served_kernel.py` SHA-256 as `helper_sha256`. Each digest has `bytes` and `sha256`. Its public input manifest maps
these roles to absolute regular file paths:

- `platform_tar`, `kernel_tar`, `child`, `parent`, `kernel`;
- `root_der`, `valid_pem`, `untrusted_pem`, `public_pki`;
- `client_build`, `service_build`, `toolchain`, `receipt`, `log_0` through the
  last build log.

The toolchain receipt's `tools` map records `path`, `bytes`, `sha256` and
`version` for `rustc_platform`, `cargo_platform`, `rustc_kernel`, `cargo_kernel`,
`clang`, `llvm_ar`, `openssl`, `qemu`, `ip`, `ethtool`, `tcpdump`,
`grub_mkrescue` and `python`. The runner rehashes its actual runtime executables
before and after the case. It requires exact public root embedding in the child,
child embedding in the parent, both embeddings in the kernel, and the kernel
and boot configuration at parsed ISO filesystem extents. These checks establish
bounded byte correspondence, not arbitrary compiler correctness.

## Separate routed Linux topology and verdict

`native-tls-ipv6-routed-matrix.py` owns two fresh network namespaces. Linux routes
between a guest TAP and a separate veth peer link, with explicit addresses,
MACs, MTU 1500, forwarding on the router only, and a peer return route. RA,
autoconfiguration, DAD and checksum/segmentation offloads are disabled for this
static fixture. There is no host-global firewall change. Topology, routes,
neighbors, socket census, interface identity and offload settings are retained
before and after the case. DAD and PTB/PMTU are explicitly outside this tranche.

The independent peer is Python AF_INET6 / OpenSSL TLS 1.3 using the unchanged
canonical MemoryBIO engine. It listens at the off-link peer on 4443 and guard
4444 and accepts only the selected guest source/7401. Full successful encrypted
recv/send bytes and digests are retained, bounded at 65,536 bytes per direction.
A partial or uncertain socket operation cannot produce a passing case.

The runner consumes every frame in both the QEMU guest-link capture and the
Linux peer-link tcpdump capture, with no unexplained frame or partial suffix.
It permits MLD only from Linux sources: the router on the guest link and either
Linux end of the peer link. A checksum-valid guest-originated MLD frame refuses.
It verifies Ethernet/IP tuple, checksums, exact hop decrement, ND router versus
peer roles, MSS 1440 and 1500-byte path bounds. Every complete TCP packet needs
its exact counterpart on the other link. It reconstructs gap-free streams,
refuses conflicting retransmissions, compares both streams to the actual Linux
socket bytes and checks ClientHello SNI, TLS 1.3 and ALPN. Capture timestamps
order each individual capture; no guest/host or cross-capture clock mapping is
claimed. Capture loss must be zero.

P01 requires the authenticated 2,048-byte HTTP response, close_notify exchange,
and actually captured FIN plus subsequent acknowledgement in both directions.
Native CLOSE acceptance alone establishes none of those wire facts. P02 requires
the native UNKNOWN_ISSUER refusal, no authenticated HTTP and at most 1,024 bytes
of guest pre-authentication ciphertext. L07 requires the exact capability denial
and no TCP/ND or peer acceptance. All cases also require the unchanged typed
child report, original deadlines, child exit, pipe fencing, restored
process/handle/pipe/cell census and zero sockets. Frame census equality is not
claimed. Driver reason accounting keeps the first-four exhaustive destination
policy and its readiness ambiguity; it never subtracts or tolerates errors.

Run the 44 authored controls separately on the VM before native cases. They are
finite data/cleanup/identity controls; synthetic TLS record bytes are not a TLS
or native positive. The runner writes the actual native/peer/wire/topology,
public input and cleanup records under a fresh occurrence and seals all regular
artifacts. A forced process-group retirement, replaced namespace identity or
unfinished namespace cleanup fails the case. The enclosing existing durable
producer owns original execution identity, finite lease, resource limits and
collection; this source adds no supervisor framework.

## Replacement and handoff bounds

The logical service is the private HTTPS request capability. Its current
implementation is the existing stack plus TLS actors; route/profile selection
is static constructor input. No live replacement or state export is added.
The parent fences the complete IPv6 configuration after the routed child ends;
fenced handles cannot be revived. A future implementation generation must
reconstruct route and authority through explicit authorized construction,
validate the successor outside that component, and refuse incompatible state.
No native Rust layout is a transfer schema. Post-effect rollback and hardware
handoff remain unproved.

The bounded proposition is that these exact selected actors preserve the
existing TLS and channel policy while sending one HTTPS conversation through
one explicit exact-peer route. Source review and finite controls are practical
here because the route/grant mechanism is unchanged; the source handoff records
formalization consideration and all runtime unknowns. Broader route selection,
PTB, dynamic configuration, general Internet trust/time policy and live
replacement require their own scope and evidence. The integration steward owns
acceptance. The runtime owner retains minimal public/raw/source replay evidence,
retires exact targets/ISOs/test substrate after custody dependencies end, and
retires fixture-private keys after their final live consumer. Public replay may
need fresh authorized PKI and rebuilt actors rather than retained private keys.
