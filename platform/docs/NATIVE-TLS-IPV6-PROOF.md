# Private IPv6 HTTPS proof source

This opt-in fixture covers only P01 (authenticated HTTPS), P02 (unknown
issuer refusal), and L07 (the wrong-port CONNECT request is denied before
any TCP frame). It is
separate from every existing IPv4 TLS runner, reference and verdict.
Actual product `328322a3` passed 42 TLS, 203 default-network,
215 DHCP-enabled network and 17 SSH host tests. Proof `a1421600` had
28 passing controls and one failing positive fixture: it expected the
nonexistent `peer-tcp-dns` label instead of the pinned classifier's
`peer-tcp`. The two-label correction at `e19d7431` passed all 29 controls
in fresh occurrence `8e2eadf8-6a9e-4115-b32a-067ee0c17def`; the original
`b73498c2` failure remains unchanged.

Native occurrence `7a94301d-0b22-4f3a-84cf-c9ca4688c6c1` then built the
client successfully but failed the service compilation: the peer address
literal contained 15 bytes where `Address` requires 16. No kernel or native
case ran. Product successor `15582326` adds the missing zero for the intended
`fd00:ab5d::2`; this proof successor changes only its product revision,
tree and archive pins. All 29 method bodies, peer code, accepted helper pins
and case predicates remain unchanged. The old host/control results retain
the source attribution above.

Standalone product `15582326`, proof `640a0f33` and kernel `ed6a15ea`
then passed all three native cases and all 29 artifact controls in run
`ed75b197-92e1-4daa-8f3d-1beca3437789`. P01 completed TLS 1.3,
an 81-byte request and 2048-byte response body, both TLS close notifications,
and both TCP FINs with later exact acknowledgements. P02 reported
`UNKNOWN_ISSUER`, zero HTTP, fencing, 269 accepted guest ciphertext bytes
and no native CLOSE. L07 returned the complete 28-byte v2 Denied reply,
with no captured TCP or ND. The retained public archive contains 212 files
(75,779,688 bytes, SHA256
`10c9188b4937d5e1922d17d97af5a74c1c6118c23d128b96d20fcd8bf0cf3c7c`).
Independent readback `8db84004` verified every archived file and the raw
serial/wire correspondence. Cross-vendor review accepted the runtime with
F1–F5 integration fixes. Private fixture keys and disposable VM substrate
were retired after custody.

This successor composes the standalone source onto candidate 10c
`e9d8c081`, adopts its unchanged receive-setup helper, uses the named shared
RAM-policy import, bounds P02 accepted and captured guest bytes to 1024,
adds a real IPv6 handshake-failure host test and a native binary type-check
helper, and corrects this documentation. The reviewed component host run
at product `7d9efbe5` / proof `25408af0` passed 43 TLS library tests,
31 artifact methods and the four-bin ABSD type check. Its exact evidence is
recorded in the component handoff and independent review. A composed native
replay remains **UNRUN**. No historical verdict is changed, and standalone
native results are not composed-candidate results.
The composed TLS builder and binary checker use candidate 10c's canonical
patched standard library: 2251 files, 45,920,288 bytes, content manifest
`c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c`.
Preparation caught their stale standalone pin before any compiler or test ran.
The original standalone library identity remains `f4930397` with 45,919,817
bytes; its results are not attributed to this composition. The canonical
`stage-library.sh` recipe is unchanged.

The LAN-worker source-transfer refusals in native-ipv6-tls runs
`08469b49-1111-4b6d-a925-ab7a332f4fc7` and `cd35bdb9` remain unchanged.
The later exact owned-Vultr-VM action `a73396f7` passed normal controller
review with those refusals, the owner's explicit VM source-transfer
authorization and the changed destination disclosed. Its successor
`b73498c2` produced the host and artifact results above. Neither action
retried the LAN transfer or copied a private key. Future execution still
requires exact inputs and the normal controls for its actual destination.

## Actual consumer and independent peer

Composed product source `8b93d2d57dc43e321308d62e3e66d18f73214520` owns a static
on-link `fd00:ab5d::15` NIC and one exact scoped stream to
`fd00:ab5d::2:4443`, local port 7401, scope 1, IP MTU 1500/MSS 1440.
The child receives only its protocol/report pipes and no-spawn authority.
The parent observes RX setup before its 15-second grant; the child retains
its original 10-second deadline, within a scheduled 20-second invocation.
After normal child exit, the revoked owner retains the existing IPv4
fixture's 100-millisecond polling opportunity before final stream fencing.
The original invocation deadline still applies. This can submit an already
accepted CLOSE; only the independent wire predicate establishes FIN and ACK
observations. Clock/deadline refusal still reaches fencing, and failed child
execution is fenced immediately. That polling path was exercised in the
standalone native run above.

`native-tls-ipv6-peer.py` adds AF_INET6-only listeners to the unchanged
first-party `native-tls-matrix.py` OpenSSL MemoryBIO connection logic.
Linux supplies TCP, IPv6 and ND. The peer accepts only the exact native
source tuple and at most one connection. Port 4444 is a separate silent
guard. Both listeners are bound before guest launch; no synthetic readiness
connection is made. Full bounded Linux `recv` and successful `sendall`
streams are retained. A failed send can have a prefix effect; that case
fails, never retries, and makes no absent-effect claim.

P01 requires the typed native TLS 1.3 success, exact fixed HTTP request,
2048-byte patterned response, authenticated peer close, drained local
close and accepted native CLOSE. The peer independently observes the
request, ALPN, TLS version, disabled resumption and both close notifications.
P02 requires `UNKNOWN_ISSUER`, zero native and peer HTTP, one attempted
connection, no completed server handshake, at most 1024 accepted WRITE bytes
and at most 1024 captured guest stream bytes. It does not claim clean TCP
or TLS closure. L07 requires the complete 28-byte v2 Denied reply for the
issued peer, zero connections to either listener and zero captured TCP/ND.
`SERVICE DONE` alone satisfies none of these case predicates.

## Exact prebuilt inputs

Compile a clean product checkout at the revision above, separately from
the proof checkout. Kernel source is
`929a8efd7dee6a0f227c677cb453516b9a380c10`, tree
`bd1f5c036bd11875121858d20f8809548e2a87c0`. Canonical source archives
use `git -c tar.umask=0022 archive --format=tar REV`:

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| Composed product | 24279040 | `b0c298c7ea53edccad2ba6b3ce035bfc2b5f8a3e9dfb9620a6b87294440f42ee` |
| Kernel | 12451840 | `81600785cdedb0ad0e5552563da10f11c591b842b2fbc7d7e30e2c1807293f6c` |

The composed product tree is `ef8a1776a3618df3a780e83cac08534c5e653723`. Its
product/proof split permits exact native replay without a self-referential
archive pin. The helper pin for `net-matrix.py` is the candidate 10c buffer
`7d51d1861e9a7942a3cde05137ac0ba040b219c0ef18c5a68d26aea78d060b36`;
the other five helper pins retain their standalone bytes.

The `--inputs` JSON maps these role names to absolute regular input paths:
`platform_tar`, `kernel_tar`, `child`, `parent`, `kernel`, `root_der`,
`valid_pem`, `untrusted_pem`, `public_pki`, `client_build`, `service_build`,
`toolchain`, `receipt`, and contiguous `log_0` through `log_N` (1 to 8 logs).
The exact public PKI seal, public root and both selected public leaf PEMs
are copied and compared. Its validation Unix time must equal the service
selector and actual child report. No RTC or system clock is changed.

`client_build` and `service_build` are untouched output receipts from
`build-native-tls-fixture.py --ipv6 --client-only` and
`--ipv6 --service-only` respectively. Preserve all their source, lock,
root, C compiler/archiver, staged library and transport-profile identities.
Use the same sealed child for the service build. The custom aggregate
`receipt` has schema `absd-native-ipv6-tls-build/1` and:

- `case`, `tls_lock_sha256`, and `platform`/`kernel` source records with
  `revision`, `tree`, literal `clean: true`, and archive `{bytes, sha256}`.
- `outputs` entries `child`, `parent`, `kernel`, each exactly
  `{bytes, sha256}`; rich path records may live separately.
- `commands`: complete executed argv arrays including both IPv6 builder
  modes and an `external-build` command with explicit `EXTERNAL_USER_ELF`,
  `EXTERNAL_INPUT` and `EXTERNAL_EXPECTED` assignments.
- `external`: `parent`, `input`, `expected` records with paths and digests;
  the latter two identify actual empty files. Preserve their build evidence.
- `toolchain_receipt`: the exact toolchain JSON digest; `logs`: the exact
  ordered build-log digests. Toolchain JSON has `tools` records named
  `rustc_platform`, `cargo_platform`, `rustc_kernel`, `cargo_kernel`,
  `clang`, `llvm_ar`, `openssl`, `qemu`, `ip`, `ethtool`, `grub_mkrescue`,
  `python`, each with absolute `path`, `bytes`, `sha256`, `version`.

The runner compares actual QEMU, ip, ethtool, GRUB and Python executable
buffers before and after the case. It executes the recorded QEMU path;
ambient `ABSD_QEMU` is not a launcher override for this fixture. Compiler
receipts/logs still need independent readback; a checker cannot prove an
honest build merely because a supplied JSON record says `clean`.

The child must occur uniquely inside the parent, both uniquely inside the
kernel. The freshly generated ISO is checked through its actual ISO9660
critical file extents and exact boot configuration. Every evaluated input,
raw capture, serial and generated semantic fact is compared again at final
seal, including the cleanup fact produced in `finally`. No private key
bytes are copied. `--peer-key` names an owner-only existing key outside the
case directory, whose owner retains its separate retirement duty.

Commands for a fresh owned VM occurrence, with exact reviewed input identities:

```sh
python3 -B scripts/native-tls-ipv6-matrix-test.py -v
python3 -B scripts/native-tls-ipv6-matrix.py --case P01 \
  --run-id NEW-UUID --proof-revision EXACT-PROOF-COMMIT \
  --work /owned/fresh-case --inputs /owned/inputs.json \
  --peer-key /private/existing-leaf.key --lease EPOCH --timeout 90
```

P02 and L07 each use their own source-matched parent/aggregate receipt,
fresh UUID and output directory. The runner does not compile, provision,
generate PKI, acquire keys, install services or extend a resource lease.
An admitted durable outer supervisor must retain exact run/unit identities,
recovery checkpoints, progress, terminal collection and provider fallback.

## Full capture, bounds and lifecycle

All PCAP frames are retained, including Linux MLD and startup prefixes.
The unchanged accepted first-four destination-reason/R1 sidecar evaluator
decides NIC refusals. Only a private tuple profile is added to its imported
module instance. There is no new tolerance or strict-zero replacement.
The full census admits exact peer ND, exact TCP and bounded Linux MLD only.
It verifies lengths, checksums, MAC/IP/ports, ND hop 255, TCP hop 64,
handshake ordering, MSS, sequence extents, identical retransmission overlap,
gap absence, ACK bounds and positive FIN acknowledgements. Reconstructed
TCP bytes equal the complete Linux recv/send streams. ClientHello SNI,
ALPN and TLS 1.3 offering are checked without claiming decrypted PCAP HTTP.

One original 30-to-120-second host deadline includes namespace/ISO setup;
the fixed lease must retain 45 seconds of retirement margin. PCAP is at
most 2 MiB/256 full frames; serial and logs at most 8 MiB, each ciphertext
stream at most 65536 bytes, and peer events at most 1024. Output directories
are fresh. No routes or clocks on the enclosing host are changed.

Cleanup considers original owned process groups even after their leader
exits. Forced retirement makes the case fail. Namespace creation attempts
are reconciled after timeout; unknown/replaced identities are retained and
fail. Dev/inode is checked before and after querying namespace PIDs before
deletion. This is a private single-producer fixture, not atomic exclusion
against another namespace mutator between final stat and delete.

Boot PIT time, host monotonic time and PCAP timestamps are distinct. Raw
terminal ticks are converted by the pinned runtime formula; no host/guest
subtraction proves effect ordering. Scheduled pre/post checks do not preempt
spawn, pipe, console or engine calls and cannot recall submitted effects.
Continuous non-icount VM clock behavior is an explicit setup assumption.
This profile adds no DAD, MLD report emission, routed TCP, PMTU recovery,
general Internet trust/time policy, kernel ABI or live-replacement mechanism.

The 31 authored artifact methods use synthetic serial, packet, ELF and ISO
critical-directory fixtures. Their positives establish only parser/oracle
behavior, never real TLS, Linux delivery or a bootable synthetic ISO. The
29 predecessor methods passed in the standalone run; the 31-method successor
suite passed in the reviewed component host run at `25408af0` and is included
in the candidate host checks. This is artifact-control evidence, not a native
composed result. Tests cover typed-case substitution, deadline/tick units,
stream/capture/peer disagreement, malformed wire, incomplete close,
cleanup/content mutation and namespace/process ownership boundaries.

Formalization consideration: the durable proposition is exact-buffer
correspondence plus bounded authority/cleanup state, under unchanged engine
and private single-producer assumptions. Source reasoning and concrete
controls are proportional now; a model would still need syscall, compiler,
OpenSSL and hardware correspondence. No Rust layout is exported replacement
state. A successor needs fresh authorized construction; fenced handles and
past wire effects cannot be revived or rolled back. Root owns source review
and storage; the integration steward owns candidate composition and
independent integration acceptance. Source run
`26662a6c-3969-4f96-a688-2a3dda07d736` owns this draft and its receipt;
review/temporary-artifact disposition is due 2026-10-18.

## Candidate 10e replay preparation

The current input pins select product 8b93d2d57dc43e321308d62e3e66d18f73214520 and kernel 8 929a8efd7dee6a0f227c677cb453516b9a380c10. The product commit includes the reviewed IPv6 HTTPS carry, health/mtime composition, the F1 lexical source-reference classification repair and corrected staged-library release metadata, and the admitted DNS advisory carry with explicit standalone feedback-proof scope. The reviewed component host-test text is corrected separately from native execution claims. The subsequent proof commit changes only this document and the replay input constants, avoiding a self-referential product archive pin. These are fresh replay inputs, not a native PASS for this pair. All earlier standalone and composed receipts retain their original source attribution and verdict. Host/type-check results are recorded separately; this composition launches no guest.
