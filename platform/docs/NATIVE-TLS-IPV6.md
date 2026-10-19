# IPv6-backed HTTPS fixture

The existing HTTPS fixture can explicitly select an IPv6 native stream channel
with `run_ipv6`. Its caller supplies one exact IPv6 address, scope and port;
the separate NIC owner still constructs the stream grant. This address does
not create authority. The TLS engine, certificate name, HTTP Host, roots, time
policy, deadlines and byte budgets are the same as the IPv4 fixture. Existing
`run` and `NativeTransport::new` retain their IPv4 behavior and wire codec.

The adapter owns either the IPv4 or IPv6 framed client for its entire lifetime.
It never switches families, reconstructs a dropped pipe, retries an uncertain
WRITE or expands the granted peer. IPv6 uses the existing version 2, family 6,
28-byte header and exact address/scope/port checks. Malformed replies, channel
loss, clock rewind and deadline expiry fence the owned client. Local accepted
bytes remain observations of capability service submission, not peer receipt.

The first intended native consumer is the current parent/child HTTPS fixture
with an exact static on-link IPv6 peer. Its parent retains the only NIC handle;
the child receives only its dedicated pipe. IPv6 TCP currently requires the
on-link 1500-byte Ethernet IP MTU and advertises MSS 1440. This adapter does not
enable routed TCP, PMTU discovery, a resolver policy, DAD, automatic address
configuration or a new trust/time policy.

Private native actors are authored as `https_get_ipv6` and
`tls_ipv6_service_probe`, built with `build-native-tls-fixture.py --ipv6`.
The initial selectors are P01 (ordinary HTTPS), P02 (untrusted certificate)
and L07 (the CONNECT request for the wrong peer port is denied before
any TCP frame). The parent waits for the
existing RX setup interval before issuing its exact stream grant and spawning
the pipe-only child, under one 20-second invocation bound. Its grant lasts
15 seconds and the existing child retains its original 10-second deadline.
The parent requires one typed report, retires the channel, gives an accepted
CLOSE 100 milliseconds of scheduled polling within the original invocation
deadline, then fences its stream table and checks process/handle/pipe/cell
restoration and NIC loss counters. This matches the existing IPv4 fixture's
polling opportunity; it does not guarantee a FIN acknowledgement or natural
TIME_WAIT retirement. A clock or deadline refusal still reaches local fencing
before returning the error. Failed child execution is fenced immediately.
The continuous VM clock/setup assumption remains explicit. Standalone product
`15582326` and proof `640a0f33` passed native P01, P02 and L07 against Linux
in run `ed75b197-92e1-4daa-8f3d-1beca3437789`. The composed candidate
successor adds review fixes; those historical results remain attributed to
the standalone revisions.
The invocation deadline is checked at scheduled pre/post-call observations;
it is not a physical completion guarantee or syscall preemption mechanism.
In particular, spawn has no timeout, startup write has its own 1000-tick
timeout, and console output or exact-child reap can outlive the deadline.
Post-call clock/deadline refusal prevents later protocol submissions; it
cannot recall an earlier effect. SERVICE DONE records typed child/resource
closure. An independent runner must separately check the selected TLS case's
actual authentication, HTTP, refusal and wire outcomes.

The host library suite now includes a `run_ipv6` handshake-failure case that
feeds an invalid TLS record through the actual framed client, observes the
fatal alert, checks the pre-auth byte/attempt budgets and fencing, and requires
zero HTTP. `scripts/check-native-tls-ipv6-host.py` also type-checks all four TLS
binaries with dummy DER and ELF include buffers. It uses the existing staged
ABSD target because Linux-target compilation omits their native APIs. It does
not link or boot a guest, and its dummy inputs make no PKI or executable claim.

## Boundary and replacement consideration

The durable proposition is that explicit family selection retains one exact
stream authority and its terminal failure behavior while the TLS state machine
remains shared. Local tests exercise real IPv6 framed-client parsing with
fragmented reads/writes, short stream writes, EOF, Again, malformed identities,
unknown WRITE completion and clock/deadline refusal. Real stream Session
controls exercise wrong address, scope and port before any NIC frame. Passing
these controls is not native Linux interoperability or TLS authentication
evidence. The existing TLS authentication tests must also continue to pass.

Practical boundary tests and this source-level argument are sufficient for
this small adapter. The decision owner is the S2 lane owner, subject to the
integration steward's independent review. No new state machine, wire schema,
dependency or kernel interface is introduced. Tests do not model physical DMA,
clock accuracy, scheduler progress or post-effect rollback.

The owner service and configured peer have logical identity; this issued pipe,
client and TLS session belong to one implementation occurrence. Continuing the
service identity never revives a fenced pipe. A successor
requires a fresh explicit owner grant and a new TLS session. There is no
replacement state export, native Rust layout transfer, automatic rebind or
downgrade claim. Quiescence requires stopping new submissions, fencing the
pipe and resolving or refusing any unknown submitted effect; dropping this
client is not proof that a NIC queue or remote peer is quiescent. Live kernel
generation transfer remains a separate architectural obligation.
