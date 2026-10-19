# Compatibility Without Architectural Capture

Owner's architecture principle, recorded 2026-10-11 during the C ecosystem
campaign. It sits beside [DESIGN-INFLUENCES.md](DESIGN-INFLUENCES.md)
(G9 to G11 on personalities and adapters) and the maturity roadmap's
compatibility rings. It is a principle to point back to, not a work item:
it admits no campaign, lane, ticket or implementation obligation.

**Compatibility is something ABSD offers, not something it owes.**

ABSD is an operating system with its own authority, resource, process, and
failure semantics. Its purpose is not to reproduce Unix, Linux, or another
existing system, nor to differ from them merely for the sake of novelty.

Native interfaces should be shaped by native workloads and demonstrable
guarantees. Existing operating systems provide useful ideas and hard-won
experience, but their historical decisions are not automatically ABSD's
obligations.

## Principles

**1. Native semantics remain authoritative.**

Compatibility facilities adapt foreign software to ABSD's model. They do
not silently redefine that model. Any proposed native mechanism must be
evaluated on its own merits, including its effects on isolation,
authority, resource ownership, lifecycle, and failure behavior.

**2. Honest incompatibility is preferable to fabricated compatibility.**

An unsupported operation must be refused explicitly rather than
approximated in a way that falsely claims its guarantees.

Compatibility claims require evidence. Untested behavior is unclaimed
behavior. Each supported compatibility surface should have a documented
semantic contract, qualification evidence, and known limitations.

**3. Compatibility must not introduce ambient authority.**

Foreign personalities should remain userspace components operating
through explicitly granted capabilities wherever feasible. They must not
silently introduce global namespaces, Unix credentials, implicit
privilege, or unbounded authority inheritance.

A compatibility requirement does not itself authorize a kernel change.

**4. Compatibility may reveal legitimate native requirements.**

Foreign applications are useful adversarial consumers. A port may expose
a missing facility that native ABSD software would also benefit from.

The deciding question is:

*Now that this workload has revealed a requirement, would native ABSD
benefit from a facility providing these semantics?*

Such discoveries should inform native design without automatically
importing foreign APIs or their historical implementation constraints.

**5. Prevent semantic capture as well as authority capture.**

A compatibility layer can preserve capability boundaries while still
imposing hidden obligations on filesystem semantics, shared state,
process lifecycle, synchronization, or scheduling.

Compatibility must not silently weaken or expand native guarantees to
satisfy foreign expectations.

**6. Compatibility is a maintained liability.**

Every personality, adapter, and behavioral exception incurs ongoing costs
in testing, documentation, security, and evolution.

Compatibility surfaces require identifiable ownership, evidence labels,
explicit unsupported cases, and a maintenance budget.

Where feasible, foreign personalities should remain independently
removable without compromising native operation.

**7. Difference is not a virtue by itself.**

ABSD should reuse established abstractions when they are appropriate. An
interface does not become undesirable merely because Unix uses it.

Equally, ABSD should not distort a better native interface to make it
resemble an established one.

Native workloads, including existing ABSD services and applications,
should resolve these choices through evidence rather than architectural
identity.

## Decision rule

When a compatibility requirement conflicts with native design, ask:

1. What observable behavior does the application actually need?
2. Can existing native facilities provide that behavior faithfully?
3. Would a new facility independently benefit native workloads?
4. What new authority, timing, lifecycle, and maintenance obligations
   would it introduce?
5. Can the compatibility behavior remain isolated and removable?
6. If the required semantics cannot be supported honestly, should ABSD
   explicitly refuse them?

A compatibility feature is successful when it provides its claimed
behavior without compromising ABSD's native guarantees, not merely when
foreign software runs.

## Architectural intent

ABSD should be capable of learning from Unix, BSD, VMS, and other
operating-system traditions without becoming a reproduction of any of
them.

Compatibility expands the software ABSD can use. It does not determine
what ABSD must become.

**The objective is not to be unlike Unix. The objective is to be ABSD.**
