# First-class bounded judgments — deferred direction

Disposition: `BOUNDED_JUDGMENTS_CAPTURED_AND_DEFERRED`, by owner direction,
2026-10-04. This records a possible ABSD contract for judgments; it selects
no implementation, protocol, kernel object type, or milestone. It is not a
U1/U2 blocker. Read with [ownership boundaries](OWNERSHIP-BOUNDARIES.md),
[the usability roadmap](USABILITY-ROADMAP.md), and
[live evolution](LIVE-EVOLUTION.md).

## Judgment is evidence, never authority

A judgment is a scoped evaluation of named evidence under a declared schema
and resource budget. It may inform an independently authorized decision;
it never grants authority, selects itself as authoritative, or directly
causes an effect. A planner, evaluator, or interface presenting a judgment
does not thereby gain the right to apply its recommendation. Admissibility
and execution belong to the owning authority and operation contract.

**Uncertain judgments can be first-class; uncertain authority cannot.**
A wrong judgment can mislead its consumer. Separating evidence from authority
does not prove judgment truth, confidence calibration, admissibility, or the
correctness of the policy that consumes it.

ABSD owns this boundary independently of Constellation. Jev and Clef are
examples for exploring evaluator roles, not ABSD product dependencies,
required engines, or implementation choices. No current evaluator or model
integration is claimed by this note.

## A conceptual contract, not an API

One possible shape is:

```text
judge(schema_id, evidence_handles[], deadline, budget)
    -> schema outcome, confidence?, provenance, evaluator generation, receipt
```

This is a shape only: no callable API, wire format, syscall, mandatory
confidence score, or signed-receipt requirement is adopted. Schemas may be
versioned service contracts; they need not become kernel object types.
A future named consumer must specify what the schema means and what its
result can establish. A schema might, for example, define `service_health/v1`
with finite results `HEALTHY`, `DEGRADED`, `FAILED`, `INDETERMINATE`. These
example values describe the judgment, not an operation disposition.

A finite schema may be satisfied by a deterministic rule engine, a Jev-like
or Clef-like component, a governed remote evaluator, or a human operator,
under its declared evidence and budget contract. Consumers need not depend
on a model choice. Sharing a schema does not establish equal truth,
reliability, or performance. Schema registration remains a conceptual
admissibility question; no registry implementation is selected.

Keep the concepts distinct:

- Schema identity/version and the question, subject identity/generation,
  admissible evidence, outcome meaning, and refusal conditions.
- Exact evidence references, observation scope, provenance, and limits on
  completeness, freshness, and availability. A handle or digest alone does
  not establish any of these properties.
- A bounded budget for execution, memory, evidence input, and result size;
  an explicit deadline in an identified clock domain and cancellation or
  interruption meaning. Wall time does not grant authority or prove ordering.
- Evaluator logical identity and implementation generation tied to existing
  release/source/artifact identity, together with relevant configuration.
- A retained receipt or evidence pointer identifying the request, evaluator,
  inputs, limits, scoped result, and operation disposition.

Under the [existing operation vocabulary](OWNERSHIP-BOUNDARIES.md#outcomes-describe-operations-not-transport-status),
`COMPLETED` would establish the evaluation contract's stated postcondition,
not the truth of a prediction. A completed evaluation can return the schema
outcome `INDETERMINATE`. `REFUSED` covers a specified effect known not to
have occurred; `INDETERMINATE` describes unresolved evidence about that
operation. None of these names changes syscall statuses or process
termination `Outcome`. A bad judgment, refusal, timeout, indeterminate
result, or unavailable evaluator never directly authorizes an effect.

## Low-authority replaceable userspace

Evaluators should be bounded userspace components with only explicitly
permitted evidence access and resources. They cannot broaden their own
explicitly delegated evidence scope or mutate judged objects through ambient
authority. Inference, tokenization, prompts,
vision runtimes, and model-specific policy remain outside the kernel.
Future kernel involvement, if a consumer demonstrates it, is limited to
generic identity, handles, accounting, transport, and cancellation contracts;
this note implies no new kernel primitive or present cancellation facility.

Replacement must preserve logical identity separately from implementation
generation. Quiesce or reconcile in-flight evaluations, fence predecessor
authority, validate the successor independently, and retire old generations
under the resource contract. Any exported state uses an explicit versioned
schema, conversion preconditions, and loss/refusal rules; native Rust layout
is not a transfer format. Rebinding is authorized explicitly and never
revives a fenced handle. A receipt from an old evaluator generation remains
identified as such; replacement cannot silently relabel it as current.

Possible consumers include diagnosis, lifecycle observation, selection among
independently authorized recovery plans, RT observation without scheduling
or admission authority, foreign-ABI observations, and a future console.
These examples scope questions, not work orders or dependencies.

## Small learned instruments adjacent to mechanism

Design guidance recorded by user direction, 2026-10-05; no roadmap item or
implementation admission follows. **Models may advise mechanism; they do not
define authority, truth, or correctness.** Small learned/statistical components
may eventually classify bounded observations, score alternatives, identify
anomalies, or suggest one of a finite set of independently qualified profiles.
They remain replaceable userspace instruments outside the kernel boundary.
Jev-shaped describes the bounded judgment role, not a dependency or chosen
model. No general-purpose model, accelerator, or memory floor is required.

**Removing, disabling, or mistrusting the model must make the system less
adaptive or less perceptive, not less correct.** Basic correctness, recovery,
and established timing/resource bounds must survive absence, refusal, timeout,
arbitrary output or a wrong judgment. An authorized deterministic consumer
may ignore the judgment. A model choosing a label does not authorize the
profile or effect associated with it.

    observation -> bounded/versioned input -> small judgment component
                -> judgment / uncertainty / refusal
                -> deterministic admissibility -> optional authorized effect

A future consumer must qualify execution time and memory, finite input/output
contracts, explicit unknown/refusal, replayable inputs, versioned model and
configuration identity, observable provenance, and a deterministic fallback.
Hidden state requires an explicit model and lifecycle contract. Reproducibility
must be sufficient for the stated replay/debugging claim; determinism cannot
be assumed from small size. Selection among pre-qualified tuning profiles
still needs qualification of the selection/transition path and its bounds.

Possible uses are advisory workload classification, resource-pressure or I/O
observations, device-health interpretation and failure triage. These are
examples, not permission to modify the scheduler, RT admission, drivers,
authority checks or recovery. Learned output cannot create/widen authority,
authorize operations directly, invent actions, or become opaque correctness
state. **The kernel may consume judgments. It must never require faith.**
That maxim admits no model syscall, model runtime, kernel weights or inference
machinery today; existing generic userspace contracts remain the boundary.

## Questions kept open

A future admission must decide evaluator eligibility and independent result
acceptance; evidence/schema admissibility; stale-judgment handling; identity
pinning; result and receipt retention; validity of old-generation receipts;
in-flight replacement, cancellation and lost replies; and the restart or
coexistence contract. It must distinguish a result's remaining evidential
value from permission to act on it now. Reliability, confidence calibration,
and replay correspondence require their own stated assumptions and evidence.
No evaluator supervisor, judgment registry, lifecycle framework, or new lane
is selected here.

## Formalization consideration

Learned-instrument addendum source: canonical kernel
`8ff3680` atop runtime `85efdcd94df7cf8f83b91c64988841a884736237`.
Result is a design constraint, recorded by the controller from user direction.
Proposition: correctness and established bounds survive removal or arbitrary
judgment, while effects retain independent authority. Counterexamples are
loss of recovery when a model is absent, a wrong label escaping a qualified
bound, or weights deciding authorization. Prose suffices for this deferred
note; no such consumer exists here and no runtime property is proved. A later
admitted consumer should model finite selection/transition and execute removal,
timeout/refusal and arbitrary-output controls against its deterministic
fallback. No implementation or qualification lane follows from this capture.

Source identity: kernel base `f2c200b4c4b13662b582adb478cfdbb1260b74c4`,
tree `67f8dd60e8bbd13886202fb1bd2de87632a5dd2c`; the source, doctrine,
coordination, and proposed document hashes are in the design capture receipt
for run `c8ac65f1-87bc-4974-b416-46f949737f1b`. Decision owner: ABSD's
architecture owner; any later implementation requires separate admission.

The design propositions are that judgment is evidence rather than authority,
schema outcome is distinct from operation disposition, and evaluator identity,
resource bounds and replacement evidence remain explicit. Counterexamples
include treating confidence as a grant, accepting a stale judgment for a new
generation, and claiming a timeout means the requested effect was refused.
Prose and source correspondence suffice for this direction-only change: no
runtime transition or behavioral proof is introduced. Concrete schemas,
acceptance policy, deadlines, cancellation, receipt validity and replacement
semantics remain unknown. A future admitted contract should consider a small
bounded model with explicit construction correspondence; this capture opens
no model or qualification lane.
