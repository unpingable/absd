
### Composition follow-ups: explicit identities and rejection output

The additive W01 checker now requires `--platform-revision`, `--platform-tree`,
`--kernel-revision` and `--kernel-tree`. Supply the four full Git identities from
that occurrence's admitted source record, independently of `CASE-INPUTS.json`.
The checker compares them to the hash-bound case record and still requires its
literal clean-state fields. `--runner` names the exact candidate9 runner buffer
(SHA-256 `9f82fc85874f61eb300ff635548cc80ad000803c8854e52b25acc2fb1635fbbd`).
Its bytes and all three evaluated JSON buffers are checked again before sealing.
This makes a composed platform and kernel admissible without silently deriving
expectations from the record being checked. Caller review must still establish
that this runner actually produced the canonical occurrence; providing its bytes
alone does not establish execution or build correspondence.

`native-tls-rejection-evidence.py` is a separate additive receipt for P02, P02b,
P03, P04, P05 and W03. Give it the same source/runner arguments, `--case-dir`, the
three `--result-sha256`, `--fixture-sha256`, `--case-inputs-sha256` custody hashes,
`--pcap-sha256` for `tls.pcap`, and a separate new `--output` path. It binds the
complete captured client TCP stream (including equal retransmissions) to every
Linux recv digest. After the pinned 239-byte ClientHello it requires exactly
`140303000101` and one 24-byte encrypted record starting `1703030013`, with no
extra bytes. OpenSSL must have authenticated/decoded the exact fatal-alert reason
for the selected certificate or handshake failure. The receipt retains the exact
30 per-run bytes and their digest. Ciphertext is session-specific: there is no
constant encrypted-alert vector, and this checker does not independently decrypt
it. The decoder observation, native failure, boot/census/cleanup, source/build and
clock ordering remain separate claims with their original canonical evidence.
The old 42 native occurrences remain attributed to their old source and runner;
they are not rerun or relabeled by these new artifact controls.

The error-output loop now refuses `accepted >= 1024` and uses saturating budget
subtraction. Attempt, deadline, fencing and HTTP authority conditions are
unchanged. A new host case exercises the actual framed adapter's over-count
refusal before a second error-output write. Source-identity substitution,
complete-byte correspondence and stream negative controls are finite tests of
this bounded oracle. They do not establish safe kernel-generation replacement;
no exported state, ABI, authority transfer or live replacement mechanism changes.
Independent delta review owns composition of these changed oracle claims.
