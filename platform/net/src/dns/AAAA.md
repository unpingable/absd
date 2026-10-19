# Bounded AAAA lookup

`Resolver::lookup` retains its A question and `Answer` result. The added
`Resolver::lookup_aaaa` returns `AnswerV6`, whose address elements are 16-byte
network-order IPv6 addresses. A question type and result width are paired by a
private trait implemented only for four-byte and sixteen-byte arrays. Both
entrypoints share the existing transport, transaction-ID sequence, deadline,
retry limit and retirement state. An AAAA result does not create an endpoint
grant. The resolver transport may use either address family independently of
the requested DNS record family.

The same limits apply: eight distinct addresses, eight CNAME transitions, 64
records across all sections, two UDP transmissions per question, one 3000 ms
lookup deadline and at most 4096 bytes for an explicitly delegated TCP
fallback. Only answer-section records at the current CNAME owner satisfy a
question. An address of the other family does not satisfy it. No automatic
A fallback, address synthesis, DNS cache, DNSSEC or encrypted DNS is added.

The parser now checks IN AAAA RDLENGTH equals 16 even in an A response. A
CNAME sharing its owner with either A or AAAA data is refused. These tighten
malformed-input handling; ordinary A queries, response types and named
consumers in `dns_client.rs` and `tcp_client.rs` retain their interface.

UDP truncation never yields a partial answer. Without separately delegated
TCP authority it returns `Truncated`. With that authority it submits the same
question and transaction ID under the original absolute deadline. A TCP reply
with a mismatched question is malformed; another truncated reply is refused
without recursive fallback. Timeout retires both resolver entrypoints.

## Formalization consideration

Decision owner: Codex S2, subject to independent integration review. Source
base: `4475746a90e5dd13961fa8de0c9848975e29d85f`. The exact successor commit
and validation result are recorded in the lane handoff. The scoped proposition
is that the selected entrypoint fixes both query type and address width while
preserving the bounded engine's ID, timeout, CNAME and transport-authority
behavior. The private trait supplies the type correspondence. Independent
literal DNS wire vectors and negative cases exercise family substitution,
malformed lengths, alias loops and depth, record/address exhaustion, TCP
truncation and native denial/interruption. Practical tests and this prose are
sufficient for this small extension because it reuses the existing state
machine and introduces no concurrent execution or new authority constructor.
This is not a proof of transport correctness or DNS authenticity. Exact-peer
filtering and bounded operations remain obligations of `Transport`.

No replacement-state schema is introduced. Resolver identity remains the owned
transport and nonrepeating local ID history; this state is not serialized. A
replacement must fence the old transport and construct an explicitly granted
successor; it cannot revive retired channels or infer grants from results.
Uncompleted operations, outstanding DNS replies and externally visible sends
prevent claiming transparent state transfer or rollback from this change.

Native IPv6 transport, AAAA answers observed from an independent Linux peer
and existing A consumers require integration execution. Source-only checks
are not those results.
