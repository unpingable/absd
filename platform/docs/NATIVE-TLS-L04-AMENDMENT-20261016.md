# L04 window-check applicability amendment, 2026-10-16

Decision owner: integration steward git-55, admitted at 01:48:17Z on
2026-10-16. This amendment applies only to fresh occurrences bound to its
runner identity. Earlier results and their criteria remain unchanged.

The successful backpressure case L03 requires a receive window of zero and
subsequent reopening when the consumer resumes reading. L04/full-rx instead
kills the consumer during its read pause, with the receive queue still full.
Its dedicated checks require a zero window immediately before interruption,
the interruption's timing inside the pause, independent wire evidence, the
measured killed exit and restoration of resources. The old generic branch
additionally required reopening for L04. That added L03's resume-reading
objective to a case deliberately interrupted before reading resumes.

The correction is one applicability condition: the generic zero-and-reopen
branch applies when `wire_zero_window_required` is set and
`require_zero_window_before_interrupt` is absent. The entire dedicated L04
branch is unchanged. L03's reopening requirement remains unchanged. Fixture
bytes, pause and interruption times, source executable, case manifest,
deadlines and all resource/authority checks remain unchanged.

The original full-buffer interruption occurrence remains FAIL. Its observed
zero window before the kill and absent reopening explain the finding; they
do not turn that failed occurrence into a pass. A fresh L04 occurrence must
establish every dedicated timing, queue, wire, exit and cleanup predicate.
Independent review attaches exact original and fresh evidence identities to
the campaign receipt. This amendment alone establishes no new native result.

Formalization consideration: the claim is an applicability distinction
between resume-reading and interrupted-while-full cases. Direct predicate
inspection and independent source/log/packet correspondence suffice for
this bounded correction. It is not a theorem that every implementation is
incapable of reopening after interruption, and it makes no claim about all
concurrent histories, scheduler preemption or kernel replacement. No product
state, authority rule or runtime ABI changes.
