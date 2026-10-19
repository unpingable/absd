# Private native HTTPS fixture

This isolated workspace implements the development experiment in
`docs/NATIVE-TLS-EXPERIMENT.md` and coordination issue #33. Its current consumer
is `https_get`, launched by `tls_service_probe` with one exact-peer native stream
capability for `10.0.2.2:4443`. It is excluded from the operator image.

The client requires `runtime::startup_stream_handles()`, which observes the
validated startup record's input and output capabilities without duplicating
them. Its diagnostic console is a separate result pipe. Missing stream roles
refuse startup; the console is never substituted for protocol output.

The client uses rustls 0.23.46 and ring 0.17.14, TLS 1.3, standard certificate
chain/signature/name/time verification, and required `http/1.1` ALPN. The owner
provides the public fixture root, `absd-fixture.test` name, Unix validation time
and immutable capability expiry. Fixture RDRAND, trust and time choices establish
no Internet deployment policy. Resumption is disabled. There is no reconnect or
replay after an uncertain WRITE.

I/O accepted-byte counters record positively acknowledged progress. A missing
or malformed WRITE reply does not establish zero effects: bytes may already
have entered the native queue. The consumer drops the pipe and never replays
that request; its typed native error remains part of the result.

`PIN.json` records the admitted 14-package TLS union. `DEPENDENCY-CLOSURE.json`
partitions those packages from existing native dependencies and off-target lock
entries, with exact archive, manifest and licence-file identities. Its static
feature analysis requires confirmation with locked offline Cargo feature trees
on the admitted cloud builder before compilation. The ordinary root, SSH,
integration and staged standard-library locks are unchanged.

The cloud sequence is input closure, public PKI seal, final provenance,
host tests, native build, independent controls and native cases. The public
DER files under `fixtures/native-tls/pki/*.der` are generated ignored build
inputs with a separate `PUBLIC-PKI.json` seal. Private keys stay outside this
worktree and ordinary evidence. After source seal, public DER generation is
enumerated separately from Git source identity.

The builder accepts explicit `--stage`, `--cargo-home` and a new `--receipt`
path. Set `ABSD_TLS_ROOT_DER` and `ABSD_TLS_ROOT_SHA256` from the public PKI seal.
`--client-only` builds `https-client.elf` once. Each `--service-only` build
requires `ABSD_TLS_CLIENT_ELF`, `ABSD_TLS_CLIENT_SHA256`, `ABSD_TLS_CASE` and
`ABSD_TLS_UNIX_SECONDS`, and reuses the exact child while embedding the selected
parent into a fresh kernel occurrence. The receipts record actual selectors,
root, child, target, locks, staged sources and removed compiler overrides.
The cloud wrapper owns capacity admission and execution; this script grants no
additional resource or execution authority.

Host tests include the HTTP parser, actual framed native adapter exchanges,
bounded live gate transitions, fallible fixture time, standard certificate
verification and local input refusal before CONNECT. The verifier test needs
the separately generated public PKI and `ABSD_TLS_UNIX_SECONDS`. It reports an
unused malformed intermediate separately: a valid direct chain can ignore it,
so that observation is not a malformed-chain refusal claim.

Success requires the exact complete HTTP response, authenticated peer
`close_notify`, drained local `close_notify` and accepted native CLOSE.
Native EOF is measured separately. Short HTTP with authenticated TLS close
retains `HTTP_INCOMPLETE` through bounded cleanup. Cancellation, expiry,
clock refusal and uncertain IPC drop the owned pipe; closed or fenced state
cannot issue more I/O. `max_crypto_ms` is the maximum observed wall-clock span among initialization,
packet processing, plaintext writes and close-notify calls. It does not measure
all crypto CPU or establish a preemption bound. The gate tests exercise the actual transition helper,
not rustls cryptography, kernel scheduling or total memory behavior.

This connection is single use. There is no exported live TLS state, authority
transfer, generation rebind or restoration from native Rust layout. Replacement
requires a fresh authorized grant and handshake; externally emitted bytes and
fenced handles cannot be rolled back or revived.
