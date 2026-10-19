# L09 reservation assertion amendment, 2026-10-16

Decision owner: integration steward git-55, admitted at 01:57:26Z on
2026-10-16. The original L09 occurrence remains FAIL; this source correction
does not reinterpret its verdict or establish a fresh native result.

The fixture successfully held eight endpoint reservations and the ninth grant
returned typed Exhausted. Its parent then required eight live TCP sockets and
failed. Native stream grants reserve endpoint-table entries with no socket;
CONNECT creates the TCP socket. A fresh fixture with unconnected grants has
zero sockets. Existing stream tests and independent native source/log review
establish that distinction.

The correction is limited to the Err(Exhausted) guard in the granting parent
`tls_service_probe`: require eight retained reservations, zero sockets before
the ninth request and an unchanged socket count afterwards. The eight success
paths, ninth typed refusal, cleanup, wire checks and external runner criteria
are unchanged. This changes the parent fixture binary, not the HTTPS consumer,
native network library, TLS implementation, runner or case manifest. A fresh
L09 occurrence must rebuild and identify that parent before claiming coverage.

Formalization consideration: reserved endpoint authority and a connected TCP
socket are distinct states. Direct source correspondence, the existing stream
tests and the actual ninth-grant refusal justify this small fixture correction.
The evidence establishes the named table limit, not allocator exhaustion,
recoverable OOM or a total memory bound. Kernel objects, capability semantics
and implementation-generation transfer are unchanged.
