# Directional ARP proof successor

Source attempt `171b2d52-b2a5-4f27-852c-0b1d278b0428` adds a separate
`native-echo-matrix-arp.py` runner and `native-echo-matrix-arp-tests.py`
artifact controls. Every input from corrected core
`9dc11cb42bdc7008c5a3003b68d9ed95b597cbcd`, tree
`b9cab64ac77c7e6da735826f17be4502a6fccff1`, including the original runner,
its tests and build/manifest/lock inputs, remains byte-identical. The original
runner's all-zero ARP target-hardware rule does not correspond to the actual
locked smoltcp request producer. That is a source finding before execution,
not a failed Echo native result or a retroactive verdict change.

The exact two configured MAC/IP pairs and existing ARP tuple, source, length,
padding, paired-reply and Echo predicates still apply. Requests are directional:

| Producer | Ethernet destination | ARP target hardware |
| --- | --- | --- |
| Guest smoltcp 0.14 neighbor discovery | ff:ff:ff:ff:ff:ff | ff:ff:ff:ff:ff:ff |
| Linux peer neighbor request | ff:ff:ff:ff:ff:ff or exact guest MAC | 00:00:00:00:00:00 |

Replies retain exact peer MACs in both fields. This is the narrow observed
producer profile, not general ARP compatibility. No peer identity, tuple,
protocol, Echo body/checksum/correlation, one-request/no-retry, authority,
finite-bound, normal-exit or cleanup predicate is relaxed.

The artifact source retains the literal 60-byte guest request observed in
native DHCP run `46771e55-9091-4c55-8abd-cf98b1fc3173`, zero-based frame 12,
frame SHA256
`161373db3a1188391be4fa2f50c61e581f527a762a8941469636cc3515df9e2f`.
Its enclosing raw PCAP SHA256 is
`fc2c88865999ee230df09a026dc3405670f3fdc1d9d164f1a726fd76aefd5fc0`.
The source-backed correspondence finding is in shared registry run
`ce55e736-fc36-403b-ae72-582288e56302/ARP-CORRESPONDENCE-FINDING.json`;
SNTP source correction run `7ecc4d49-ab5a-47a8-ac5c-f8a9dedb4d0d` records the
same locked producer profile. The literal is independent of the new artifact
ARP writer. Four new artifact methods check this literal and directional
Ethernet/target-hardware substitutions; all ten prior Echo controls are
preserved, with their synthetic guest ARP builder corrected to the same
actual producer profile. All 14 methods remain unexecuted by this source task.

The runner records required corrected core revision/tree/run and exact hashes
of the core, consumers and selected build/manifest/pin inputs in LAUNCH and
RESULT. It reads each supplied ELF once, retains exact buffers and requires
unique child/parent/kernel embedding as before. Those observations do not
establish which source produced the ELF. The resource owner's separate build
receipt must pin the corrected source inputs, actual toolchain/dependencies
and resulting child, parent and kernel ELF hashes. A core-identical additive
runner successor is acceptable when that correspondence is recorded.

After source readback, the admitted resource owner uses the existing serialized
VM envelope and exact prebuilt ELFs:

```sh
python3 scripts/native-echo-matrix-arp-tests.py
python3 scripts/native-echo-matrix-arp.py /owned/fresh-echo-proof \
  --kernel-elf /owned/absd-kernel \
  --elf /owned/echo-service-probe.elf \
  --client-elf /owned/ping-once.elf --timeout 120
```

The original proof document's isolated IPv4 Linux-kernel peer, TCG CPU/256 MiB,
private fresh namespace/TAP, no host route/service/clock changes, no public
contact, exact-buffer ISO/PCAP/serial sealing, output bounds, owned process
cleanup, canonical FAIL and explicit UNRUN scopes apply unchanged. A positive
Linux-kernel Echo exchange would remain unauthenticated diagnostic evidence;
boot-domain scheduling/RTT is not a physical precision or DMA-recall claim.
No compiler, artifact case, protocol, QEMU, provider or guest is executed here.

The queued first-read red/green input is exactly
`net/src/echo/tests.rs::delayed_first_partial_or_full_start_read_retires_before_request_execution`
at pre-fix source `3316321c1a62042cd697406275e1859c264c3866` and corrected
`9dc11cb42bdc7008c5a3003b68d9ed95b597cbcd`. Four controls cover partial/full
START reads at +250/+251 ms. Their source assertions retain consumed read bytes
but require no response/socket/request submission and a stale endpoint. The
pre-fix expected failure is reasoned from source until separately executed.

Formalization consideration: two fixtures that share an invented ARP
assumption do not establish correspondence to the actual producer. The sealed
literal native frame plus directional positive/substitution controls address
this bounded profile. Practical source review and these deterministic artifact
controls suffice for the disposable runner; complete capture, truthful Linux
interfaces, pinned build receipts and no concurrent mutation of the fresh
mode-0700 directory remain assumptions. This is no proof of arbitrary ARP,
physical deadlines, authenticated identity or runtime-tool substitution.
Root and the independent steward own the disposition.

This is an additive proof implementation generation. It transfers no live
state or authority, revives no fenced handle, defines no exported transfer
schema and provides no kernel/device replacement or post-effect rollback.
Release/main/U1/supported ABI holds remain. Root owns the 32 MiB source
allowance and aggregate storage budget. No new runtime resources are created.
Retain minimal commits/receipts for source/build/review correspondence; root
retires this exact worktree after integration/review/replay users end. Actual
execution owns its separate admitted output allocation and retires reproducible
staging/scratch after exact dependency checks. Next custody review: 2026-10-17.
