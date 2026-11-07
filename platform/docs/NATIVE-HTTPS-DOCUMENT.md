# Native HTTPS document command

`https-document` is an opt-in Preview 2 consumer of the native exact-peer
stream capability. It fetches one configured HTTP/1.1 200 response, accepts
one Content-Length of at most 16,384 bytes, and publishes a body and receipt.
The initial implementation uses the existing userspace smoltcp and rustls
TLS 1.3 paths. It adds no kernel socket interface or protocol implementation.

Historical source milestone `2fa74b02` passes 161 independently reproduced host Rust
tests, including 11 Linux OpenSSL peer cases and the SSH and shell tests.
These are not current-freeze results. Host results do not establish the native process, grant, filesystem or image
path. Native build and guest evidence are recorded separately at integration.

## Build and configuration

The ordinary image has no enabled document command or network grant. Build
with `ABSD_HTTPS_DOCUMENT=1`, an owned `ABSD_TLS_STAGE`, an isolated public
`CARGO_HOME`, and a fresh `ABSD_HTTPS_DOCUMENT_RECEIPT`. The existing builder's
`--document-app` mode builds the command without fixture certificates, time
or case selectors. Set the same opt-in when assembling the operator image.
Run native builds and guests on the separately admitted disposable VM.

For release assembly and `release_manifest.py build`, export the same
`ABSD_HTTPS_DOCUMENT=1`, `ABSD_TLS_STAGE` and
`ABSD_HTTPS_DOCUMENT_RECEIPT` used by the successful native build. The manifest
records `build.https_document.enabled`, the native receipt digest, canonical
ring stage metadata digest, TLS lock, target and staged standard-library source
fingerprints. It refuses an installed command without explicit selection, or a
receipt whose source revision/tree, stage, lock, target or command bytes do not
match. The command is required even for a partial manifest when selected.
Ordinary releases record `enabled = false` and retain their usual command set.

Reconstruction of an enabled release requires `reconstruct-release.sh
--tls-stage DIR MANIFEST`: provide the same public, pinned ring stage through the
existing staging procedure. Stage metadata must match the manifest. The script
sets the selection explicitly, supplies a fresh build receipt under its work
directory and compares the rebuilt installed command with the release artifact.
The existing toolchain/Cargo cache prerequisites still apply. A source path or
receipt digest alone is not dependency delivery. Older manifests with no App A
selection reconstruct only when they contain no App A artifact. Preserve the
original native receipt with the release evidence; it is an input identity, not
an independent reproduction result.

`ABSD_BUILD_RECEIPT` also includes `commands/https-document` when selected:
begin removes a previous command, finish requires its newly produced bytes, and
the media qualifier checks the selected on-disk command against that receipt.
This establishes installed membership. Its bounded boot command sample does
not execute App A; native fetching and recovery retain their own evidence.
The existing TLS fixture notice declaration does not inventory this shipping
application: its resolved target dependency closure and generated release
notices must be qualified before publishing an enabled image.

Supply these two public configuration files using the existing operator
image `--etc` input. `/etc/https-document.conf` contains exactly four ordered
lines, for example:

```text
peer=192.0.2.2:443
name=document.example
path=/one.txt
issuer_spki=THE_64_LOWERCASE_HEX_DIGITS_OF_THE_ISSUER_SPKI_SHA256
```

`/etc/https-issuer.der` contains the directly signing issuer certificate in
DER form. Pin its public key, not its name or entire certificate hash. For
an operator-held public PEM certificate, obtain the SPKI digest with:

```sh
openssl x509 -in issuer.pem -pubkey -noout |
    openssl pkey -pubin -outform DER | sha256sum
```

The configured IPv4 address is the only network destination. The lowercase
DNS name supplies TLS SNI, hostname verification and HTTP Host; it does not
trigger a DNS lookup. Redirects, compression, chunked framing, multiple
destinations and reconnect/fallback are unsupported. Missing configuration
refuses the command. The issuer is a pinned trust anchor: validity checks
cover the directly signed leaf across the complete bounded time interval;
issuer-certificate validity and revocation are not asserted.

## Operator invocation

An ordinary no-network command samples the current boot ID and clocks:

```sh
ssh -T operator@GUEST /bin/https-document --sample
```

Its stderr contains the boot ID, PIT milliseconds and RTC seconds. Attest
UTC milliseconds corresponding to that sample using an operator-trusted
clock, including sampling and transport uncertainty. The declared uncertainty
must be at most 1,000 ms. This command neither sets system time nor establishes
the truth of the operator's clock.

Invoke the exact direct executable without a PTY, substituting the attested
values:

```sh
ssh -T operator@GUEST /bin/https-document --boot BOOT_HEX32 \
    --pit-ms PIT_MS --rtc RTC_SECONDS --utc-ms UTC_MS --uncertainty UNCERTAINTY_MS
```

The existing SSH server must use its direct argv execution mode. It owns one
pending or active document invocation, appends the original 15-second grant
expiry, and delegates only the configured stream plus existing FSD access.
Shell invocation does not receive this network grant. Protocol stdio belongs
to the native channel; diagnostics and the final receipt path use stderr.

The trusted SSH launcher checks the resolved program and refuses alternate
spellings of a fetching invocation. The native shell also refuses a resolved
document fetch before opening files or starting pipeline stages. `--sample`
remains an ordinary command. These checks govern the established launchers;
the receipt does not cryptographically attest an issuer identity or prove
that an arbitrary other authorized launcher used native TCP. Caller-selected
argv and bytes on ordinary stdio cannot establish that provenance.
An operator can produce a bundle in the same format by running a copy of the
command as an ordinary exec, which gets no network authority, or by writing
the files directly; the receipt therefore does not prove that the issuer ran.

The clock interval advances conservatively using both PIT and RTC, with an
upper advance of `max(PIT elapsed, RTC elapsed + 1 second)`. Missing or
regressed clocks, a changed boot ID, excessive clock disagreement, an interval
wider than five seconds, or an anchor age reaching 15 minutes refuse further
work. Reboot requires re-attestation. Both clocks stopping together remains
an explicit trust limitation. Preview 2 entropy uses the existing bounded,
CPUID/carry-checked RDRAND implementation and fails closed; this is not a
production cryptographic-entropy claim.

Bound the sample's UTC using the operator's send and receive times, including
trusted-clock error and measurement delay. A midpoint estimate needs declared
uncertainty covering at least half that interval plus those errors; refuse
attestation if it exceeds 1,000 ms. Do not substitute a server-provided UTC
claim or silently enlarge the precision limit. Emulated PIT loss can cause
availability refusals under the two-second PIT/RTC agreement check; native
qualification must record that behavior rather than relaxing the bound.

After the handshake the engine checks the immutable direct leaf at both ends
of a finite certificate-coverage window extending 15 seconds beyond the
current upper time bound. Later pump passes check only that fresh actual
clock bounds remain usable and contained in that verified window. Actual
uncertainty remains at most five seconds. This avoids repeated signature work
while conservatively refusing a leaf close to expiry before sending HTTP.

## Result and interrupted work

Success prints `/home/operator/https-document-ID/receipt` on stderr. That
exclusive bundle contains `body` and the versioned `absd-https-document/1`
receipt with configured identity, checked time intervals, length and SHA-256.
The receipt describes local validation at publication, not a signed remote
receipt or protection against a later writer.

The command synchronizes both newly created files and uses the existing
no-replace directory rename. It publishes only after complete framing,
authenticated TLS closure, native close acceptance and fresh certificate,
clock and original-expiry checks. A refusal prints no success path. An
interruption or uncertain storage effect may leave a staging or final bundle;
preserve it for exact inspection rather than assuming rollback or retrying
the same occurrence. Session cancellation fences networking; the issuer
retains the FSD binding until actual child reap before it admits another child.

There is no live TLS, HTTP or capability-state transfer. Restart requires a
fresh invocation and grant; a successor cannot revive fenced handles. Existing
release, candidate and U1 holds remain independently controlled.

A failed fetch with an engine report prints one `absd-https-failure/1` line
before the unchanged generic refusal; exit status remains 1 and stdout stays
empty. Its fixed field order and shared Rust/Python vectors are in
`fixtures/native-https-document/failure-v1.tsv`. Outcome, phase and TLS codes
come from closed tables; unrecognized values become `OTHER`, and absent TLS
codes become `NONE`. If ErrorOutput is absent, all five trailing fields are
`NONE`; a present output uses decimal counters, 0/1 booleans and `NONE` for no
output error. The line is ASCII with one LF, at most 512 bytes; the maximum
with the current tables and 64-bit counters is 349 bytes including LF.

These counters describe local TLS queue and native-write acceptance, never
peer receipt or alert delivery. No body, certificate, key or dynamic protocol
text is included. Early refusals without a report retain only the existing
generic message. This operator record changes no transport, drain, authority,
policy or deadline and is not an exported runtime-state transfer schema.

## Replacement recovery of a published bundle

A published body and receipt are ordinary durable application state under
`/home/operator`. Keep their configuration and issuer in `/etc` with the
same recovery point. Use the strict procedure in
[P2-REPLACEMENT-RESTORE.md](P2-REPLACEMENT-RESTORE.md); an in-place writable
resume is a separate operation and does not reconstruct this application.

Before taking a point, complete a fetch, record its printed receipt path,
and read both its body and receipt back through authenticated SSH. Check the
expected body length/hash and configured identity. Then shut the machine down
orderly and wait for its QEMU process to end. For example, with an already
configured operator directory `operator/app-a` and selected release ID
`preview2-app`, create and verify a new private point:

```sh
python3 -I scripts/release.py backup --target operator/app-a points/app-a --recovery-point
python3 -I scripts/release.py verify-backup points/app-a --recovery-point-sha256 POINT_SHA256 --expected-release preview2-app
```

Replace `POINT_SHA256` with the exact digest reported by successful point
creation, retained outside the point. A point contains the complete image,
site data and host-key seed; keep it private. The RPO is that clean halted
state. Every later change can be lost, including a fetch or other write that
completed before a later unclean stop. Record the actual point-to-stop interval
when qualifying a recovery; that observation is not a zero-loss guarantee or
a maximum backup-age policy.

After an unclean stop, retire the exact old execution and preserve its failed
image. Do not reset its guard, reuse it as the restore destination, or infer
that an interrupted publication rolled back. A network-held request shows an
in-flight fetch, not an observed filesystem pre-rename boundary. Inspect any
retained staging/final paths in the failed image as observations, preserving
uncertain outcomes. The qualification driver's held SSH client uses authenticated
server-alive probes every five seconds, with three unanswered probes allowed.
This bounds detection of a lost VM on an established connection; connection
setup timeout alone does not. Failure to terminate within the driver's separate
30-second wait is an infrastructure failure, with partial output retained.
Local client cleanup cannot satisfy the interruption check, and no remote EOF
or application timeout is inferred from VM loss.

Restore the independently pinned point into a fresh target:

```sh
python3 -I scripts/release.py restore points/app-a --target operator/app-a-recovered --recovery-point-sha256 POINT_SHA256 --expected-release preview2-app
ABSD_QEMU='qemu-system-x86_64 -accel tcg' scripts/boot-operator.sh operator/app-a-recovered 2222
```

Use the exact qualified QEMU configuration for the selected release. Only one
copy of the logical machine may serve. Verify the expected release, listener
and retained public SSH host fingerprint as described in the operator runbook.
Read the saved body, receipt, `/etc/https-document.conf` and issuer back and
compare them with the point. Confirm the declared absence of a known post-point
write. The old receipt retains its historical boot/time fields; do not rewrite
it or treat them as a current invocation or restored network authority.

Sample the new boot using `/bin/https-document --sample` and obtain a fresh
operator-trusted clock attestation. Invoke the direct command with those new
values as above. Old boot IDs, grants, TLS state and attestation arguments do
not resume. Verify the new body's bytes and receipt, sync any additional new
application write, shut down cleanly, boot the same replacement again and read
all those new bytes back. A successful image-copy message alone does not prove
usable or durable App A recovery.

If the boot refuses `RELEASE REFUSED reason=release_mismatch`, retire and retain
that failed execution/image. Reconstruct the intended point release in another
fresh directory and repeat the configuration, host-identity, fresh-attestation,
fetch and clean-restart checks. Do not select a release on the failed image to
turn the refusal into a recovery result. Corrupt-point and wrong-point admission
refusals retain the existing strict P2 contract; they are not a substitute for
this application readback and new-fetch evidence.
