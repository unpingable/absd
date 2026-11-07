# Experimental native TCP fragmentation-needed refusal

Existing issue #34 tracks this follow-up. Live consumers are the native
`stream::Client`/owner, `dns::tcp::DatagramTcp` fallback and TLS
`NativeTransport`. This source candidate adds explicit opt-in refusal, not
path MTU discovery or connection recovery. All new tests/build/native execution
are UNRUN at authoring. Root owns the separate Linux-router/native probe and
oracle; independent review and steward acceptance remain separate.

## Why refusal

Pinned smoltcp 0.14.0 emits ordinary IPv4 TCP packets with DF set. Its generic
IPv4 emitter sets identification zero, DF true, MF false and offset zero.
Its TCP effective segment size comes from private Interface MTU and peer MSS;
there is no public existing-connection PMTU setter or ICMP-to-TCP update hook.
This candidate does not change the dependency or engine. A known lower-MTU
path may still need a separately configured immutable Stack MTU, and actual
PMTU recovery remains outside this candidate.

## Explicit construction and wire version

The owner chooses `Stack::stream_grant_mtu_refusal(grant)` or
`stream::Session::grant_mtu_refusal`. The channel convenience constructor is
`stream::channel::Channel::grant_mtu_refusal`; the matching delegated consumer
uses `stream::Client::new_mtu_refusal`. Merely supplying an address or request
does not enable the policy. Legacy outbound v1, inbound v3/family4, IPv6
channels, SSH and their constructors retain their original selection.
No kernel ABI, startup role, dependency or default network configuration changes.
The default Port contains empty bounded observer storage; with no opt-in grant,
hooks return before parsing or adding Link clock/status reads.

Experimental `stream::mtu::VERSION` is 4, family/reserved byte 0. It uses the
existing two-byte big-endian frame length and 12-byte native stream header.
The frame body is exactly 12 bytes for this error (prefix `00 0c`):

| Header bytes | Meaning |
|---|---|
| 0 | Version 4 |
| 1 | Original requested stream opcode |
| 2 | Status 17: FragmentationNeeded |
| 3 | Zero |
| 4..8 | Exact granted peer IPv4 |
| 8..10 | Exact granted peer port, big-endian |
| 10..12 | Reported next-hop MTU, big-endian; metadata, no following body |

Rust exposes `stream::Error::FragmentationNeeded { mtu: u16 }`. Only the v4
client decodes status 17 and accepts MTU 576..1499 with no body. Unknown status,
wrong peer/version/family, extra body or implausible metadata fails the framed
transaction. The client fences on this terminal error and never retries WRITE,
reconnects or renews its caller's absolute deadline. Other v4 success/error
shapes remain the existing stream shapes. A v1 client refuses these new bytes;
no automatic protocol negotiation or supported-ABI promotion is claimed.

DNS has explicit `dns::tcp::Session::grant_mtu_refusal` and
`DatagramTcp::new_mtu_refusal` constructors. Its UDP leg stays v1; only its
pre-granted same-peer TCP leg is v4. Construction rollback and paired revoke
remain bounded. `dns::Error::Stream` preserves the typed refusal and the failed
TCP exchange makes the transport unusable without reissuing the query. This
does not make ICMP advice trigger DNS TCP fallback: a matching UDP TC answer
and paired authority are still required for ordinary resolver fallback.

TLS has explicit `NativeTransport::new_mtu_refusal`. Its existing generic
native-error adapter retains the cause as `Outcome::Native`, drops its owned
pipe and performs no replay. Ordinary TLS engine entrypoints still choose the
legacy constructor; they are not silently switched to the experimental policy.
New end-to-end TLS opt-in selection would require its own explicit consumer
integration. No trust, certificate, name, ALPN or time rule changes.

## Observation, matching and retirement

Only an opt-in owner grant registers a slot checked against its local epoch.
There are at most eight registered flows, four successful submissions per flow,
and one sticky terminal error per flow. The history is a fixed FIFO ring: every
new successful matching submission replaces the oldest slot, including repeated
wire keys. A record is eligible for at most 1000 ms, inclusive. Intervening ACKs
or retransmissions can evict a data record even before that bound; no guaranteed
refusal or delivery liveness follows from this finite history. A local queued
WRITE or failed Link send creates no successful-submission record.

The observer accepts only complete checksum-valid engine TCP submissions with
IPv4 IHL20, DF and no fragments. It records original total length,
identification/flags, source/destination addresses and the first eight TCP bytes
(ports and sequence). Thus matching also names the actual submitted IP length.
TTL, TOS and IPv4 checksum are excluded from the key because a router may change
them; each quoted IPv4 header checksum is nevertheless validated.

Incoming advice must be a complete, checksum-valid, unfragmented outer IPv4
ICMP type3/code4 directed to this owner's MAC and local IP. Reporter IP/MAC
must be unicast and nonzero; self/network/broadcast reporter addresses are
excluded. The unused ICMP field must be zero. The quote must contain the full
20-byte original IPv4 header and at least the first eight TCP bytes; it may be
a longer truncated original prefix, as in a Linux 576-byte ICMP packet. The
quoted original need not be fully present. A full TCP checksum cannot be
validated from a minimum quote and is not claimed. Options, quoted fragments,
wrong protocol and malformed/truncated headers are ignored.

Only MTU >=576 and strictly below the matched submitted IP total length can
produce refusal. Zero/unspecified, smaller policy values, equal/larger MTU,
unmatched, evicted, aged or empty-scope quotes have no effect. This floor is
an explicit candidate policy, not universal IPv4 minimum-MTU conformance.
Advice must match a recent record belonging to the current registered slot.
Clock rewind and original grant expiry invalidate history/pending advice.
A rewind observed by an observer hook is latched and propagated through the
existing typed Clock error even when that sample is newer than the endpoint's
last maintenance sample; it cannot leave an indefinitely stopped but
connected-looking grant. Existing stream clock/timeout rules retain precedence. New advice cannot
refresh the original endpoint lifetime or the client/frame deadline.

The receive hook only latches a sticky fault and marks the matching tuple's
egress stopped. It does not remove sockets while Interface owns its receive
borrow. The TxToken gate prevents subsequent output from that tuple in the
same poll; unrelated streams, UDP and classic SSH flows remain admitted by
their existing rules. Stream maintenance, outside the Interface borrow, removes
the matching socket and its queued bytes without trying a reset, retransmission
or MSS change. A typed terminal error/reserved slot remains until explicit
owner close/abort/revoke, so the error can be delivered through the channel.
All endpoint operations then refuse; they cannot queue new bytes. Explicit
revocation releases the reservation and old references become Stale.

Successful earlier WRITE means local enqueue; earlier submitted bytes may have
escaped before advice and their remote effects remain unknown. A prepared
response to an earlier transaction may already be in the pipe. Removing local
queues does not undo either effect. A failed Link send may have had an effect
although it enters no successful-submission history. No physical cancellation
or rollback is asserted. The remote TCP connection can remain open; an
independent fresh positive fixture should use a distinct local port rather than
assuming the same wire tuple immediately reconnects after local retirement.

Registration/history clears on revoke, close, abort, link fence and slot reuse.
The terminal reservation does not mint a fresh grant. No automatic route,
MSS, replay, reconnect, regrant, lifetime renewal or background probing occurs.

## Evidence and bounded qualification

Fourteen new net methods in `net/src/stream/mtu_tests.rs` author controls for
minimum and longer Linux-style quotations, checksums/header/tuple/sequence
substitutions, MTU policy, history eviction/age/rewind/expiry, scope reuse,
equal-wire provenance limits, actual two-engine submission/deferred socket
removal, failed TxToken submission, version4 metadata, actual client no-retry,
paired DNS selection/revoke and original deadline refusal. The actual queued
output case includes an advice-free positive control so Nagle cannot make its
zero-output comparison vacuous. One additional TLS method checks real adapter
cause preservation, pipe fencing, accepted-prefix history and no replay.
These methods are authored only; run the complete existing net default and
DHCP variants and TLS tests off-host, retain raw full counts/harnesses and do
not infer execution from source enumeration.

Root's prospective native proof must measure a successfully submitted DF TCP
packet larger than the actual lower router egress MTU (proposed 576), not infer
packet size from a 1024-byte application WRITE. It must retain the genuine
Linux router's ICMP3/code4 and complete quoted-prefix/submission/capture
correspondence, actual native Client/Session v4 refusal and endpoint retirement.
A separately authorized new grant with a different local port can calibrate
ordinary Linux application delivery. This does not validate same-connection
PMTU recovery or a pipe-only native child unless that consumer is actually run.
No current or former VM is contacted by this source task.

## Formalization and evolution

The finite proposition is scoped: a plausible quote matching bounded recent
successful current-grant submission causes terminal refusal for that grant,
not another flow, with no implicit replay or new authority. Practical actual
method tests, independent byte fixtures and native full-capture observations
are proportionate; no general Internet or scheduler theorem is claimed.

Equal quoted wire bytes do not authenticate a router, implementation generation,
application transaction or historical packet. After rebind, empty history
refuses old advice; after an equal new submission, equal old advice can correlate.
The explicit host counterexample preserves this limitation. The first eight
TCP bytes do not uniquely identify data content or ACK/flag history.

Observer records belong to this Stack implementation generation. No state
transfer mechanism is added. Replacement must quiesce receive/egress and pending
pipe replies, retire old sockets/queues, validate a versioned exported schema
and reconstruct authority explicitly. The new v4 protocol is explicit; native
Rust layout or a copied epoch is not a transfer format. Retained tombstones
and uncertain earlier effects constrain rollback. Independent acceptance is
owned by the integration steward, with Root as engineering allocator/reviewer.

Source is forecast at 40 MB, actual allocation/capacity in the lane receipt;
60 GiB must remain free independently on `/` and `/data`, with no per-lane quota.
Creator retains the source for review/composition/rollback until dependency end
or Root review2026-10-19T00:00:00Z. No compiler targets, VM, key or runtime is
created by this source task.
