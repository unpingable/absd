# W02 criteria amendment, 2026-10-16

Decision owner: integration steward git-55, decisions at 00:05:39Z,
00:16:51Z and 00:19:53Z on 2026-10-16. This amendment applies only to new
occurrences explicitly binding `W02-20261016-UPSTREAM-RUSTLS` and the new
manifest/runner hashes. It never changes earlier results or historical criteria.

Run `8f19e82c-1e8e-4c39-9c4a-ed3f3a567b88` on source
`e480bf347dd4a98d33ab73f6deb126fc347be013` failed W02: the native consumer
read the five-byte header `1703034101`, then returned Deadline rather than
the originally required TlsRejected. That FAIL remains the original verdict.
Private-rustls commits `60dc697a`, `06292db3` and `0eb4f058` were not admitted
by the steward and are removed from the continuing source. Their actual runs,
including failures and interruptions, remain evidence of that separate line.
The test-only ClientHello drain in `06292db3` modifies a test introduced by
the removed patch, so there is no unchanged application of it on e480.

The fixture bytes and timing stay unchanged: after an authenticated request,
the independent Linux peer sends only that header, declaring ciphertext length
16,641, with no record body or HTTP response. RFC 8446 sections 5.1 and 5.2
bound TLS 1.3 ciphertext to 2^14 + 256 = 16,640 bytes and require termination
with record_overflow for a longer record. Upstream rustls 0.23.46 instead uses
a shared framing threshold of 2^14 + 2048 = 18,432, rejecting lengths at or
above that threshold. The TLS 1.3 decryption limit is reached only after a
complete body. With this header-only fixture, the engine waits for more input.

For newly admitted W02 occurrences, the required native outcome is Deadline
or Truncated, zero delivered HTTP body bytes, no response plaintext sent by
the peer, a fenced consumer pipe, the unchanged absolute operation/grant
deadline, no reconnect, and the existing resource/handle cleanup checks.
Cleanup and report completion may follow the deadline; their measured times
do not establish preemptive deadline enforcement. No operation gains a later
deadline and there is no new timing tolerance or authority extension.
Success and accepted response plaintext always fail. The independent Linux
OpenSSL control retains its separate TlsRejected expectation. No other case
or success predicate changes.

This qualifies bounded deadline refusal for the named consumer, not immediate
RFC record_overflow handling, a delivered fatal alert, a whole-process memory
bound, or general TLS conformance. The upstream divergence remains a finding;
an upstream issue may be drafted separately but publication is not authorized
by this amendment. No private TLS-engine fork is retained.

Formalization consideration: the proposition is that this single unchanged
header-only fixture never yields accepted HTTP response bytes or application
success and retires the connection using the existing deadline. The executable
source is e480; the new commit changes only criteria, runner checks and prose
relative to that source. Exact commit, manifest, runner and result identities
are recorded in the lane receipt. Practical tests, exact peer-byte checks and
independent inspection suffice for this bounded occurrence. They do not prove
the proposition for every TLS input, scheduler history or allocation failure.

Primary references: [RFC 8446 section 5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1),
[section 5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2), and upstream
[rustls record framing](https://github.com/rustls/rustls/blob/f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb/rustls/src/msgs/message/mod.rs).
