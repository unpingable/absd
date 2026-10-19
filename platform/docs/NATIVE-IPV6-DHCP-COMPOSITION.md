# Accepted IPv6 and fixture DHCP source composition

This source-only composition joins IPv6 UDP/TCP runtime
9eb8b5c5ad918fb80b3ea4eec0072c5ca0cae137, including the preceding IPv6 UDP
runtime, with DHCP runtime a342e51d90d322fc803e2571e9ac57ed847c5c4f.
Both descend from candidate8 eb70b62f01681c0127095400b0625f5f831830c5.
The steward's 2026-10-16T19:14:18Z note independently accepts the preceding
UDP run 955f158d, TCP run 9cbaefed and DHCP run 46771e55 as ACCEPT_BOUNDED;
their earlier failed runs remain failed. This merged source has not been
compiled, tested or booted by its producer. Exact source/tree and checks are
in shared S2 run 687f0626-798c-4186-afcf-aaf6c5b7d41e.

The merge retains both accepted probe features and binaries. DHCP's optional
`dhcpv4` feature adds the already selected smoltcp DHCP socket to the existing
IPv6-enabled dependency. smoltcp stays pinned at 0.14.0; the lockfile and
dependency versions do not change. The root manifest hash pin follows the
combined manifest. TCP-server, Echo and SNTP source are not part of this tree.

DHCP acquisition constructs an empty private Interface before its application
Stack exists. Its Port literal now initializes `ipv6_config` to None and both
IPv6 peer arrays to empty, exactly like ordinary `Stack::open`. Acquisition
therefore gains no IPv6 configuration, routes or endpoint authority. The
post-lease Stack is still constructed fresh through the accepted path. This
composition does not make DHCP's private DNS owner a general dual-stack owner,
add DHCPv6, or permit lease traffic to issue new capabilities.

The owning documents disclose the required composition limits. The shared
paired DNS interruption fence intentionally includes IPv4 DNS fallback.
DHCP remains fixture-pinned, with a stricter conflict gate and no directed
ARP answers during probing/announcing. The accepted TCP trace's duplicate
UDP query during Neighbor Discovery is an observation, not a changed timer.
The runtime policies, protocol headers, finite grants and checked generation
construction otherwise retain their accepted source behavior.

## Minimal execution handoff

The resource owner should compile and run the composed default network suite
and the same suite with DHCP enabled on the admitted isolated compiler host:

```sh
env -u RUSTFLAGS cargo +1.95.0 test --manifest-path net/Cargo.toml --offline \
  --locked --release --target x86_64-unknown-linux-gnu \
  --target-dir "$ABSD_COMPOSED_HOST_TARGET" -p absd-net
env -u RUSTFLAGS cargo +1.95.0 test --manifest-path net/Cargo.toml --offline \
  --locked --release --target x86_64-unknown-linux-gnu \
  --target-dir "$ABSD_COMPOSED_HOST_TARGET" -p absd-net --features dhcpv4
```

The second command includes DHCP's host cases together with IPv4/IPv6 UDP,
TCP, DNS and existing ICMP/stream cases under the composed feature set. Use
the campaign's pinned toolchain, private Cargo custody and existing bounds.
`ABSD_COMPOSED_HOST_TARGET` must name the resource owner's admitted disposable
host target directory. Explicit Linux selection overrides the platform's
default ABSD target, following the existing `check-all.sh` host-suite path.
No new test is authored merely to mirror the three initializer fields.
The steward's candidate10 platform/kernel7 gate owns broader integration,
SSH/default-image checks and any native replays; these source checks do not
replace it. Existing canonical runner predicates and verdicts are unchanged.

Kernel7 is the separately owned ed6a15ea7c7c999422e1e294e139b6119619b06c
generation. Its multicast-admission/counter wording and predicate inventory
are root's separate D1 handoff. This composition changes no kernel source,
NicInfo layout, syscall, device programming or hardware ownership. Release,
main, U1 and supported-ABI holds remain in place.

## Authority, replacement and formalization

The bounded proposition is that composing these source features adds no
traffic-derived grants: DHCP's bootstrap IPv6 fields begin empty, and each
owner retains its checked endpoint construction and original fencing policy.
The merge has no running state to transfer. Old references are not revived;
live connection/lease continuity and rollback after external effects are not
established by combining source trees or passing host tests.

Future generation replacement still requires quiescing/fencing old queues,
explicit versioned state conversion and refusal conditions, authorized
reconstruction, external successor validation, device exclusion and generation
retirement. Native Rust layout is not a state schema. No live-replacement
mechanism or automatic hardware transfer is introduced here.

S2 root owns the formalization decision. Source identity checks, the minimal
initializer correspondence and existing combined host cases are proportional
for this composition. Those cases remain unexecuted by the source producer;
their prior separate results do not prove this merged feature set. No new
general state-machine proof or arbitrary interleaving claim is made.

Root owns aggregate S2 storage and this dedicated worktree's 32 MiB allowance.
No compiler target, VM, capture, package cache or key is created here. Retain
unique commits and minimal receipts through integration/review/replay; retire
the reproducible worktree when those consumers end. Next review: 2026-10-17.
