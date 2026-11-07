# Native Echo responder boundary fixture

This source-only successor uses the existing manifest feature, native probe and
build recipe. All new controls/build/Linux/native results are UNRUN. Production
Echo/DAD/Stack, kernel, ABI, dependencies, SSH defaults and TCP fixtures/oracles
are unchanged. The original accepted positive responder result at 3cd/ed126 and
later e565 source-stage control corrections retain their historical identities.
No old result is attributed to this product.

The same explicitly activated one-shot Owner first receives four literal frames:
bad ICMP checksum; a checksum-valid seven-byte short ICMP message; Echo type 128
with code 1 and valid checksum; and a checksum-valid request from off-peer
fd00:ab5d::3. The last is on-link, distinct from the one issued peer ::2. Literal
frames, both MACs and full bytes are in boundary-v1.txt. The fixture Link records
actual returned receive bytes and successful send bytes, passes them unchanged
to the original implementation, and makes no admission decision. Its ordinal
records are local fixture observations, not a new production drop counter.

Both engine neighbor entries must be warmed first: ordinary Linux-kernel
::2 NS/SLLA followed by guest NA, and an explicitly disclosed raw fixture ::3
NS/SLLA followed by the actual matching guest NA. No permanent neighbor pin is
used. The complete capture and actual native NS/NA records bind that second
exchange. This prevents unresolved-neighbor loss from substituting for an
Echo refusal. After all four actual inputs pass through Owner polling, the
same Owner must still report Again and zero possible reply effects; the full
capture must have no earlier Echo reply or guest NS resolving either peer.

Only then does a genuine installed Linux ping send its ordinary 64-byte Echo
request and receive one exact identifier/sequence/body reply. The native Owner
must observe that actual successful submission. Actual subsequent observe,
activate and retired-observe calls require Spent, Exhausted and Stale. These
are method-state assertions; no duplicate packet replay, expiry-stop, loss or
physical-time property is inferred. The native probe then retires with zero
application sockets and normal kernel terminal accounting. No global
before/after handle or full-memory restoration is introduced.

The original DAD acquisition, active lifetime at most 8 seconds and original
invocation at most 12 seconds remain. Native trace bounds do not renew them.
The entire priming/refusal/positive sequence consumes these same bounds. A
missing input, missing actual NA, malformed fixture order or unexpected effect
fails. The source-only host additions exercise the actual Owner with a recording
Link and real smoltcp replies, plus trace substitutions. Offhost qualification
must run the complete default/DHCPv4 net harness and require both new methods;
full counts and actual harness identities must be recorded rather than inferred.

Formalization consideration: the bounded proposition is consumed literal input
refusal with known engine cache preconditions, followed by actual positive
consumer reach on the same authority, then one-shot method refusal. Literal
vectors, actual Owner/engine controls and full-capture/native byte correspondence
are proportional to this fixture. They do not establish general ICMPv6
conformance, authenticated peer/wire generation, physical timing, arbitrary
concurrency or hardware fencing. Logical instance/generation and empty retired
replacement schema remain the existing contract; no state transfer or authority
revival is added. Root owns source review and the steward owns acceptance.

The author owns this source worktree and minimal receipts for review,
integration and rollback until that dependency ends or Root custody review by
2026-10-18T23:59:59Z. Forecast source allocation is 32 MiB; shared reserve remains
60 GiB separately on / and /data. This source task creates no target, image,
resource or key. Runtime is a distinct finite occurrence after the existing
TCP chain, with separately pinned product and oracle sources.
