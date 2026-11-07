# Boot-local civil clock and its owner

The kernel's software civil clock is anchored once to a bounded stable RTC
snapshot after the boot timer reset and before userspace starts. RTC bootstrap
accepts the fixed reproducible floor 2026-01-01T00:00:00Z (1767225600 Unix seconds)
through 2099-12-31T23:59:59Z. Earlier readings leave civil time unknown and retain
last_error=-116 for that RTC initialization attempt. Status reports
raw_rtc_bootstrap=before-build-floor and rtc_bootstrap_floor_seconds=1767225600;
these describe raw lower-bound eligibility, not UTC accuracy. The retained
last_error_reason=rtc-before-build-floor explains initialization even if an
adjacent later raw read crosses the floor. RTC is assumed UTC, not authenticated
or measured against UTC. Hardware failures likewise leave civil time unknown. Hardware/assembly before that point
has no software anchor. The existing x86 monotonic tick counter counts delivered
PIT interrupts; its rate conversion is 1193*3/3579545 seconds per tick. Emulation,
interrupt stalls and suspend can make it diverge from external elapsed time.
The ARM RTC remains unsupported; no ARM timer-rate qualification is claimed.

Corrections step only a separate civil anchor. They never write timer_ticks,
scheduler deadlines, RT accounting, watchdogs, TCP timers or the RTC. Forward
and backward civil steps are allowed to the explicit owner. Nanoseconds are an
arithmetic representation; they do not imply nanosecond accuracy or UTC error
bounds. Supported civil range is 1970..2099. RTC/operator/network source, last
successful sample, age, generation, staleness, and last attempt/failure are
separate. A failed network query preserves the last successful source/value.
Network sample expiry marks the estimate stale, but the estimate continues to
advance for ordinary wall-clock readers; source/quality-aware callers inspect
status. RTC and manual assertions have unknown absolute error and no invented
expiration or accuracy bound. All sources have unknown UTC uncertainty.

The state lasts only this kernel boot. No correction writes CMOS or persists
across reboot. A restarted sshd retains the kernel's current anchor, while a new
boot starts again from RTC (or unknown) and configured synchronization. There
is no kernel live state-transfer/downgrade protocol. The existing generation,
fencing and authority-transfer rules apply before any live replacement claim.

## Authority and consumers

Experimental 0x7fb2(console_write,0,0) mints Object::Clock WRITE only for root init:
PID 1, direct kernel parent and INIT program identity, plus an actual existing
Console WRITE handle. Init explicitly copies startup role 22 only to the served
external-worker catalog slot (program 30), the NIC/time-owner sshd. Neither the file server nor ordinary commands receives this grant.
Init closes its temporary mint after each worker spawn attempt. Runtime stores role 22 separately and deliberately
does not propagate it in std::process. An ordinary application cannot turn its
stdin, terminal, Diagnostics READ or absent handle into clock-write authority.
The object has no display/input/Machine rights. The trusted init/owner can use
normal explicit narrowed-handle mechanisms; this is not an implicit inheritance
or a new account-wide administrative capability.

0x7fb1(clock_write,request64,0) is the only software correction/failure update.
The exact live object/right is checked before touching user memory. Invalid
schema, unsupported source, future/over-age observation, padding, range,
overflow or generation exhaustion leaves state unchanged. The owner can record
a synchronization failure without fabricating a new successful sample.

0x7fb0(out_info96,0,0) reads public software civil time and quality. New runtime
wall_clock_seconds, standard-library SystemTime, date and existing FSD mtime/log
consumers use it. FSD invalidates its wall-value cache when the civil generation
changes, so an ordered correction is visible to its next operation. Normal time passage
keeps the existing bounded refresh budget. Unknown/corrupt observations cannot
reuse a known cached date. The legacy filesystem uses zero as unknown, so an
exact Unix epoch-zero file timestamp remains unrepresentable in that format.
No global ordering or monotonicity of file modification times is claimed
across deliberate backward steps. Unknown civil time remains unknown.
Rust's infallible SystemTime::now alone returns Unix epoch plus its existing
monotonic uptime coordinate when a usable civil value is unavailable. This
bootstrap coordinate lets the program run; it is not civil time. Cross-consumer
coherence applies when civil time is known, not to that fallback. Fallible date,
C time and FSD keep unknown/refused results; a changed file records mtime 0,
meaning unknown, even while a Rust program observes a bootstrap coordinate. An older kernel lacking
0x7fb0 can fall back to unverified raw RTC only on ENOSYS; no quality/coherence
claim is made for that fallback, and malformed new frames never fall back.

Supported syscall 30 keeps its original raw RTC semantics. Old prebuilt clients
calling 30 continue seeing hardware RTC and do not observe software corrections.
The explicit runtime hardware_rtc_seconds is used by https_document's existing
AppTime RTC cross-check and observation-only sntp_query. This preserves their
existing TLS anchor/trust policies; civil SNTP estimates do not become TLS
certificate-validation authority. NTS and trusted UTC remain separate work.

## Configured provider and operator requests

sshd's existing NIC-owner loop can run a bounded nonblocking SNTP observer;
there is no additional daemon, general service manager or NIC owner. Default
is disabled. /etc/time.conf selects one exact unicast IPv4 peer and UDP port
(default 123, explicit high port allowed), local nonprivileged port, retry
interval, maximum civil step and maximum successful sample age. It uses the
existing strict ASCII configuration parser and exact-peer datagram grants.
Changed configuration requires restarting sshd; it is not silently activated.

Each invocation has up to 3 unique nonzero random nonces, 2s per attempt and 8s
total in the original boot-monotonic domain. One server-loop pass handles at
most one receive and one send; a slow/missing peer cannot block SSH sessions. Existing SNTP header/origin/stratum/leap/era validation is reused.
The existing parser's explicit 2026..2035 era window is retained. Timeouts,
malformed/late replies, entropy failures, link loss, unavailable endpoint,
unknown current-clock read or maximum-step disagreement retire that invocation,
record failure and preserve prior civil time. The configured refresh interval is
at least 60 seconds. With the link up, timeout retries pause 1, 2, 4 seconds,
and continue doubling up to that interval. A down link closes the active
transport and waits for carrier without periodic queries or repeated failure
records. KoD, stratum refusal and other non-timeout failures use the normal
interval. Success resets the timeout sequence and restores the normal refresh
interval. Manual assertions reset retry state and preserve their cancellation
of automatic work. Retry-state changes are logged once, with bounded summaries
rather than one line per attempt.
The next query gets fresh nonce state and a fresh endpoint; no service-wide
socket/authority registry is introduced.

A successful peer transmit timestamp is anchored at local receipt as an
unauthenticated estimate. RTT is reported only as transport observation; no
symmetric-delay correction, absolute error bound, consensus or UTC
authentication is invented. Unknown previous civil time can bootstrap from a
configured estimate. The first network sample may also replace an unverified
eligible RTC anchor without the maximum-step bound. An RTC below the build
floor is already unknown and follows ordinary unknown-time bootstrap. This lets the configured unauthenticated peer select the
first network value; it confers no UTC authenticity. Automatic network corrections relative to prior network samples or
operator assertions must pass the configured maximum-step bound. An explicit
operator assertion itself is not step-bounded and supports 1970..2099, including
values below the RTC bootstrap floor.

Authenticated SSH session shells use session-control kind 19 for clock status,
clock set UNIX_SECONDS and clock sync. Only sshd performs the resulting clock
operation. Session control ends and Clock grants are not inherited by commands.
A manual set cancels an in-flight automatic query and delays the next periodic
query until its configured interval; explicit clock sync can request it sooner.
A sync request reports scheduling, not success; date --status reports the actual
last attempt. This slice reads static startup configuration only; managed
configuration trials and transport restoration are separate work and are not
installed consumers of this service.

## Wire and diagnostics

Both new frames are little-endian version 1, experimental only. Information96:
u32 version0/flags4/source8/attempt_source12; u64 unix_ns16 (MAXunknown),
successful_sample_tick24, now_tick32, successful_age_ticks40 (MAXunknown),
generation48, last_attempt_tick56, i64 last_errno64; u32 successful_peer72,
last_success_rtt_ms76; u64 max_age_ticks80; u32 attempted_peer88;
u16 successful_peer_port92/attempted_peer_port94. Flags VALID1,STALE2; sources
UNKNOWN0,RTC_UNVERIFIED1,OPERATOR_ASSERTED2,SNTP_UNAUTHENTICATED_ESTIMATE3.
Peer IPv4 is the numeric network-order address encoded as a little-endian u32.

Request64: u32 version0/op4 (set1/failure2)/source8/peer12; u64 unix_ns16,
observed_tick24,max_age_ticks32,rtt_ms40; i64 error48; u16 peer_port56, zero58..64.
RTC initialization is kernel-only. Manual requests have zero network fields.
SNTP requires explicit peer/port and bounded age. No request can select a trusted
UTC source. Shared civil-info-v1.hex and civil-set-v1.hex vectors exercise the
actual kernel encoder/parser and platform codec; role/rights tests cover denied
and stale capabilities. Native builds cover the real date/shell/sshd/FSD APIs.

Bounded volatile source=clock kernel records explain initial anchor/unknown RTC,
corrections, refusals, sync failures and observed known/unknown and stale/fresh
transitions. They name prior/current boot tick, generation, prior/new source/value
and signed delta, explicitly
unknown UTC uncertainty, and network peer/port/last successful RTT. Clock state
mutation ends before event formatting; emission touches only the bounded ring,
not display or storage. Repeated identical failure source/peer/port/errno within
60000 monotonic ticks is suppressed, with count on the next event or recovery.
The status record still reflects every latest attempt. Staleness transition is
recorded when observed by a clock reader; no independent timer/supervisor is
claimed when no consumer runs. Ring overwrite/truncation rules remain visible.
Older kernel records retain their original boot/tick identity; a current civil
anchor is never applied retroactively to invent historical UTC timestamps.

## Observable quality and recovery check

`date --status` and `clock status` share the same renderer. They label RTC and
manual assertions unsynchronized, unavailable civil time unavailable, expired
network estimates stale, and a recent unauthenticated sample as an estimate.
They show the successful sample tick separately from the last attempt/error.
Raw RTC seconds and signed civil-minus-RTC nanoseconds are adjacent samples
with whole-second RTC resolution; they reveal divergence without measuring
absolute UTC error. Delivered tick loss can affect anchor advance and age, so
no absolute accuracy or suspend-aware freshness bound is claimed.

After a link-unavailable attempt, the provider re-arms an inactive query at
the first owner poll after carrier rises; initial carrier-down does not arm the
normal hour-long interval. A query is bounded by 8 boot-monotonic seconds. A fresh manual
assertion cancels automatic work even when carrier rises on that poll. The step
limit applies to each correction after a network sample or operator assertion,
not cumulative movement. The initial eligible RTC-only anchor is exempt.
Repeated timeouts can reach the configured interval. A later recovering peer
can therefore wait until the next query after the current backoff, plus its
bounded query duration and actual owner poll gaps; there is no general
10-second recovery claim after an arbitrarily long outage.

The controlled guest acceptance check starts with no usable RTC and no network,
keeps diagnostics usable, then restores carrier with a responsive configured
private peer. Civil time must become known within 10 boot-monotonic seconds of
the observed rise if the peer is already responsive. Also hold the peer silent
through the first failed query in two explicit controls: carrier up at boot
with peer responsive at 10 seconds, and carrier rising at 5 seconds with peer
responsive at 17 seconds. Each must acquire within 10 seconds of peer
readiness. These finite cases do not override timeout backoff after longer
outages. Record actual owner poll gaps and reject a missed bound. These are controlled acceptance requirements, not a measured guest result.
The check also runs a native Rust SystemTime caller while civil time is unknown,
checks date/status stays unknown and a changed file has mtime 0, and steps civil
time forward/backward during a monotonic timed wait. Host PAL, Service and cache
regressions support those claims but do not replace this guest observation.
