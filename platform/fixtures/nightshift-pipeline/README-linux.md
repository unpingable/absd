# Linux reference fixture: real NQ → Pulse → Nightshift (→ AG)

Produced on Linux (x86_64) by `scripts/make-reference-fixture.sh`
(`scripts/reference_fixture.py`), which runs the real pinned, unpatched
Linux programs under a deployment whose names are fixed and synthetic. The
AG run of the same production is `fixtures/ag-native`.

## What is real, and what is synthetic

| Piece | Source | How it was produced |
|---|---|---|
| `nq/artifact.json`, `nq/store/nq.db` | NQ-NG 8057441 (tree 13c0b6b3) | The NQ fixture (`fixtures/nq`, `scripts/make-nq-fixture.sh`), byte for byte: the real `nq` and `nq-host-helper` observed a Linux host presented as `refhost` on 2026-10-10T23:16:18Z. Question `nq.host.load_pressure/v1`, subject `host:local`, claim `claim:host_load_pressure` = explicitly_absent. The store is a `journal_mode=DELETE` copy. |
| `nq/nq.toml` | written by the script | Qualify-only config (no watchers), at the production paths. |
| `nq/qualify-provenance.json` | the real `nq` (debug build) | `nq --json diagnostics qualify`, run again by the script and required to equal `fixtures/nq/reference/provenance.json`. |
| `request/cycle-request.json` | `tools/request-builder`, which links unpatched Nightshift e2675dd | A sealed CanonicalCycleRequestV1. All bindings come from the artifact (see `request/request-derived.json`). |
| `pulse/config.json`, `pulse/producer-public.hex` | Pulse 81c2354 schema | Written by the script. The producer key is a test key: the Ed25519 key whose seed is SHA-256 of the string `ABSD test fixture Pulse producer key, not a credential`. |
| `pulse/receipts/`, `pulse/acquisitions/` | Pulse 81c2354 release build of `pulse-nq-load-support` (three argv[0] roles) | The real producer and receiver, one acquisition each for `a1` and `a2`. The acquisition records hold the boot-clock identity, uptime and wall times. Only `a1`'s receipt is kept here. |
| `reference/empty-receipts/` | the real `nightshift cycle run` | One fresh store, no receipts. |

Synthetic, by construction: the deployment's labels (`laned-refhost-…` in
the schedule, generation, attempt, scheduler clock, Pulse authority and
producer ids), the recorded host (`refhost`), the production root
(`/tmp/absd-reference`), both test keys, and in the NQ store the host name
(`refhost`), the account (`operator`, uid 1000) and the paths NQ ran at
(`/srv/absd-reference/nq`). Real and kept, as measured on the machine the
scripts ran on: in the NQ store the load average, CPU count and uptime, and
the device and inode numbers, sizes, times and digests of the helper, the
C library and the loader; in the Pulse receipts the load figures, CPU count
and the Linux boot clock (a hash of a random boot id).

Request coordinates:

The request builder derives them from the artifact (started
2026-10-10T23:16:17.917Z, completed 23:16:18.624Z):

- recurrence: one completed slot, first_due 23:16:17Z (the second the execution started in), cadence 3600 s, standing window 300 s
- slot due 23:16:20Z (first_due + 3 s), latest admissible 23:21:20Z (+ 300 s)
- `evaluated_at` = 2026-10-10T23:16:28Z (slot due + 8 s)
- policy `max_age_seconds` 300
- `--nq-source-id nq-store-genesis:26373050-17aa-4ed9-8a41-cc27f3bcfb1f`

The request carries a proposal (workflow `workflow:host-care`, genesis mode).
The writer reads no clock, so these instants are the only time it uses. Without
support, the posture law calls a v2 artifact `clock_unqualified`. Only Pulse
support that is `current` makes the posture current (`request-derived.json`
`posture_without_support`).

Receipt freshness: the Pulse receiver sets expiry = receipt tick + 300 000 ms
on the receiver's Linux boot clock. The resolver answers `current` only on
that same clock, before expiry.

Wall clock: AG checks an observation against its own wall clock, and the
request's instants are fixed, so the script pins CLOCK_REALTIME to
`evaluated_at` + 27 min 4 s, 2026-10-10T23:43:32Z (`pinned_wall_unix_ms` in
`run.json`), for each cycle's
process tree, with the same LD_PRELOAD shim the AG matrix's Linux twin uses
(`tools/ag-linux-twin`). `produced_wall_*` in `run.json` is when the run
really happened.

## Runs (one production, one boot clock)

| run | Pulse receipts | support standing | posture current | outcome / exit | AG-style resolver (`current` request) |
|---|---|---|---|---|---|
| `empty-receipts`, `empty-receipts-2` | none | unknown | false | `posture_only` (`support_not_current`), exit 0, no AG spawn | contradictory (no intent) |
| `i-fresh-ag` (`fixtures/ag-native`) | `a2`, under a second old | current | true | `ag_occurrence_opened`, exit 0. Real ag-loopctl ran init and record-proposal, and AG's own call to the real observation resolver answered current. | current |

`empty-receipts-2` is not kept: the script requires that it normalizes
identically to `empty-receipts`, which checks the normalizer. It also
requires the resolver statuses below, and that AG alone, given the documents
Nightshift handed it, reproduces the `i-fresh-ag` store row for row.

Resolver requests follow `scripts/nightshift_reference.py`:

- `now` = evaluated_at + 300 000, and the ±TTL edges, with TTL 600 000
- `absent`
- `wrong-subject`
- `deployment-wall-at-run-end`: the pinned wall clock, with the TTL of 86 400 000 that the AG wrapper uses

For a PostureOnly observation every answer except `absent` is `contradictory`,
because `observation_resolver.rs` requires the cycle's typed intent and a
PostureOnly cycle has none.

Per-run files:

- `run.json`: exit status, the pinned wall clock, the real wall and uptime window, clock id
- `stdout.json`, `stderr.txt`
- `store-dump.json`: schema, pragmas, and every row, with JSON cells parsed
- `store-normalized.json`
- `observation-record.json`
- `resolver/`: the requests, the answers, and `summary.json`

## What differs by design on ABSD

- **Receiver clock.** The receipt here is stamped on a Linux boot clock.
  A native Pulse resolver on ABSD has another `clock_id`, so it filters out
  every receipt and answers **`unknown`**. This is exactly the
  `empty-receipts` path, and **`reference/empty-receipts` is the reference a
  native run must match**. The expected native result:
  - `posture_only`, exit 0
  - no ag-loopctl spawn
  - AG-style resolver: `current`, `current-edge`, `stale-edge` and
    `wrong-subject` all answer `contradictory`; `absent` answers `absent`
- **Per-run values.** `cycle_id` and `request_nonce` are uuid v4. `query_id`,
  `support_id`, `posture_id`, the cycle state digests, and the support's
  `evaluated_at` clock_id/tick all derive from them or from the receiver clock.
- **Paths.** Absolute paths in `pulse/config.json` and `nq/nq.toml` are
  the production's. A native deployment rewrites the paths only. Every
  identity field must stay byte-equal.

## Field-by-field comparison for a native run

1. Normalize the native store dump with `tools/normalize.py`.
2. `diff` it against `reference/empty-receipts/store-normalized.json`. It
   must be **identical**.

The normalized form holds these fields verbatim:

- Tables and row counts. Expect 1 slot row and 1 cycle row (`status=closed`,
  `version=2`) and 3 events, in the order `slot_claimed`,
  `observation_recorded`, `cycle_closed_without_proposal`. All
  `recorded_at`/`updated_at` = `2026-10-10T23:16:28Z`.
- `slot_id` `sha256:99ee6e49…`, `observation_id` `sha256:7520d161…`.
- The observation's `source_admissions`: the NQ V1 provenance, byte-equal to
  `nq/qualify-provenance.json`. It carries `provenance_id`
  `sha256:8b87aab2…`, run, evaluation and report ids, and the 3 nonclaims.
- Posture policy, input_evidence (`inputs_id` `sha256:d92a3a21…`),
  recurrence_evidence, and evaluated_at.
- Assessments: standing `support_unknown`, status `unknown`.
- Recurrence `current`. Completeness, condition and coverage axes. `current`
  false, headline `incomplete`.
- Support: `schema`, `authority_id`
  (`pulse-authority:laned-refhost-load-pressure-v1`), `observation_id`,
  `diagnostic_inputs_id`, `subject_id` `host:local`, `scope_id`
  `sha256:63018d3e…`, `artifact_ids`, standing `unknown`, no expiry, no
  evidence or contradiction refs.
- Attention: `attention_required`, `support_not_current`.
- Pragmas: `journal_mode` wal, `user_version` 0.

Only the placeholder values (`<cycle_id#0>`, `<request_nonce#0>`,
`<query_id#0>`, `<support_id#0>`, the posture and state digests, and
`<receiver-clock.*>`) may differ. In addition:

- `cycle_id` must match `^cycle:[0-9a-f-]{36}$`
- `request_nonce` must match `^support-query:[0-9a-f-]{36}$`
- the support `evaluated_at.clock_id` must be the native Pulse clock id

The resolver answers compare on `status`, `basis`, `fresh_until_unix_ms` and
`currentness` with those same substitutions.

A native run that did reach `current` support would compare against
`i-fresh-ag` the same way. On ABSD that needs receipts produced and
received on the ABSD clock.
