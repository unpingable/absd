# Source-pinned IPv6 server boundary proof

Profile `ipv6-tcp-server-boundary-close-v2` extends the positive on-link proof only
with the ordered native prelude specified in
[NATIVE-IPV6-TCP-SERVER-BOUNDARY.md](NATIVE-IPV6-TCP-SERVER-BOUNDARY.md).
All compilation, artifact controls and native execution of this successor are
UNRUN. The separate positive product 739f361b/proof 62905a5e and boundary e957e7e8/proof
c893cce4 stay frozen. The actual ceb54 failure is preserved. This composes the
fixture-only single CLOSE/child diagnostic repair f84086e1; no library semantics
change. The positive repair f84086e1/proof 877a122e remains a separate identity.

The boundary product is a5d3d746e23f3304495cff583cfd3b1612b50304, tree
c7c76f057c9bb02d7eb937f1baec6b3062fbce3c. Its prefix-free canonical Git tar is
26,634,240 bytes, SHA-256
`126174520bf0b6ea64ed2a164af92fc6fe7edc38ba3e93ba2c9be00f53a88326`.
Initial fixture c421f235 remains source-only; e957 adds a separate actual
completed bootstrap count/hex record. The oracle commit follows the product;
its exact identity is in the immutable lane source handoff, avoiding self-pins.

Kernel 2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b, tree
8763f164ddfed11aa2f55626bd8e85123c595a08 and its canonical tar remain unchanged:
12,574,720 bytes/SHA-256
`fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224`.
Served wrapper `e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`
and RAM policy remain mandatory. Net/runtime/broker/SSH/dependencies/build
script and target-bin metadata contracts are byte-identical to the base.

## Peer activation successor

The product a5d3d746 and build profile stay fixed. This oracle-only successor
composes the corrected 262f input lesson from the separate positive TCP proof.
The existing 7a5faada remains frozen and has no native boundary PASS to carry.
Fresh boundary qualification requires the complete new fixture/controls/build
and native contract; a positive-source receipt is not boundary preflight proof.

Create the TAP without any IPv6 address, inherit/check addr_gen_mode 1 and verify
its empty address list. Observe the actual running raw kernel NIC-ready line
through ReadyMarker before adding exact fd00:ab5d::2/64. Record before/after and
that observation in PEER-ACTIVATION.json. LISTEN still waits for decoded worker
stdout. These are different channels. All prior 33 control method ASTs
remain unchanged; three new actual helper controls cover activation/empty link
and raw-vs-worker readiness. Complete capture and strict counter/prefix checks
remain unchanged, with no counter reset, frame trimming or deadline renewal.
This source is UNRUN; if early traffic still makes accounting ambiguous it fails.

## Added exact checks

The new oracle requires 32 ordered `IPV6 TCP SERVER NEG` records: whole-fixture
clock, initial census, twelve exact constructor errors, finite eight-slot and
retired/fresh/stale results, separately observed 23-byte bootstrap, nine actual
literal request/reply frames, complete LISTEN, interruption, child result,
closed handles, final census and completion. Every constructor/API record must
show no sockets/TX before LISTEN. The complete LISTEN record must show one
socket and no TX; no Interface poll occurred in that phase.

The actual interruption record must contain the real nonzero process handle,
one received zero byte, ledger input/output lengths 301 each, kill return 0,
wait kind 3/status 0, then true EOF and Channel false/socket zero. It must fit
strictly before both pre-poll plus 250 ms and original negative grant expiry;
clock order cannot substitute for observation. Fallback fence is 0. Constructor
errors, stale values, reserved-field echo, literal tuples/scope, missing body,
prefix/ledger counts, kill/reap/EOF order, deadline equality and object census
substitutions have meaningful authored negative controls. Frame count equality
is explicitly not required.

A fresh positive grant must follow the negative completion and retain its exact
10-second original lifetime entirely inside the 20-second fixture bound. The
positive seven records, packet/socket body, checksums, tuple/scope context,
MSS1440, real ND readiness, sustained wrong-source separation, zero wrong-tuple
response, full 3072-byte streams, FIN/ACK/true EOF, source/build/ELF/ISO/std/metadata
and NIC counter predicates remain. After the wrong socket closes, an explicit
1100 ms monotone wait (maximum observed 2000 ms) must complete before positive
launch; its exact receipt is required. It consumes existing original deadlines.
The strict full-capture first-wrong-SYN gap still must exceed 1 second. The
unchanged `inspect_capture`, native boundary ledger checker, independent Linux
client, counter accounting, metadata/build and cleanup predicates remain.
All 11 boundary method ASTs and 18 prior positive method ASTs remain identical;
one prior positive receipt fixture acquires wait fields/times without losing
assertions. Three actual wait/receipt/capture controls plus three activation controls make 36 artifact methods.
The net module has 30 authored methods, including the two close regressions;
all execution at this composition is UNRUN.

Result schema is `absd-native-ipv6-tcp-server-proof/4`, with the unchanged
positive fields plus `native_boundary` schema
`absd-native-ipv6-tcp-server-boundary/1`. The build receipt schema remains
`absd-native-ipv6-tcp-server-build/1` because its fields/meaning are unchanged;
its required profile and exact product identities are the new ones above.

## Minimal offhost recipe

Reuse the separately admitted workflow in
[NATIVE-IPV6-TCP-SERVER-PROOF.md](NATIVE-IPV6-TCP-SERVER-PROOF.md), substituting the
exact clean boundary product a5d3d746 and its source archive, the separate boundary
oracle checkout/profile and result schema. Do not compile the oracle HEAD and
call it the older product HEAD. Source-matched public tool/std/cache identities,
actual build commands and logs remain necessary. There are no new dependencies.
Library production bytes are identical to base 629/product 739; the two f840
host controls are appended. The 301-byte negative ledgers, bootstrap, typed
grant/slot cases, actual kill/reap/EOF timing, owned-object census and fresh
positive original deadlines are unchanged. No existing result is rescored.

On the admitted Linux VM only, run the actual 36 artifact controls:

```
python3 -I scripts/native-ipv6-tcp-server-matrix-test.py -v
```

Require both new close tests in the actual default/DHCPv4 net harness when
qualifying this product, alongside all 30 server methods. Use ordinary
locked/offline net/SSH host checks or explicitly source-bound
existing evidence as Root's actual contract states; no host result is invented
here. Build the changed child and parent in isolated fresh targets:

```
sh scripts/build-native-ipv6-tcp-server.sh
```

Retain real metadata for both required-feature bins, canonical staged std c354,
actual child and parent ELFs and clean product/kernel source archives. Build the
same exact kernel 2775 with the mandatory wrapper and new parent:

```
python3 scripts/served_kernel.py -C "$KERNEL" \
  EXTERNAL_USER_ELF="$PRODUCT/ipv6-tcp-server-service-probe.elf" \
  EXTERNAL_INPUT="$CASE/empty" EXTERNAL_EXPECTED="$CASE/empty" external-build
```

Bind the new profile, product/archive and actual outputs in BUILD-RECEIPT. Arm
the existing durable collector/producer with fresh identities before waiting,
then use the same native invocation on the new oracle checkout:

```
python3 -I scripts/native-ipv6-tcp-server-matrix.py "$CASE/proof" \
  --kernel-elf "$CASE/kernel.elf" \
  --elf "$PRODUCT/ipv6-tcp-server-service-probe.elf" \
  --child-elf "$PRODUCT/ipv6-tcp-server-echo.elf" \
  --build-receipt "$CASE/BUILD-RECEIPT.json" --timeout 120
```

Retain full source/build/native output/FNV/ledgers/PCAP/readiness and independent
Linux socket evidence with exact cleanup records, including any FAIL. No new
resource, credential, compilation or test execution is part of this source task.

## Scope and custody

Malformed outer prefix, a complete oversized WRITE body, connected-data or
pending-output interruption, active socket/buffer exhaustion, foreign handle
use, clock/link/wire faults, routed or 1280-MTU listener and live SSH are not
qualified natively by this profile. A declared missing-body length is not a
complete oversize-frame proof. No physical time, authenticated peer identity,
wire-generation exclusion, full memory restoration or live replacement claim
is made. Configured-address NS maintenance remains a separate NIC-owner policy.
The finite state/literal contract plus actual future observations and negative
substitutions are the chosen bounded formalization. Root owns source scope and
review; the integration steward owns independent consequential/oracle acceptance.

The source author retains unique commits and minimal receipts through named
review/integration/replay/rollback, with disposition at dependency end or review
by 2026-10-18T23:59:59Z. Shared 60 GiB reserves on `/` and `/data` apply; the source
forecast is not a lane quota. No compiler targets, images, keys or VM scratch
were created. Future runtime substrate must have its own custody and exact
retirement under Root's separate dispatch.
