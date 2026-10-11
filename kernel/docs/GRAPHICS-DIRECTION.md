# ABSD graphics direction

Disposition: `CAPTURED_AND_DEFERRED`.

Class P4 of `docs/MATURITY-BACKLOG.md`: architecturally worth preserving,
but nothing is designed or implemented until the platform is substantially
more settled and a real workload earns it. It stays below the U1 items
(survivability, install, update, recovery, exact hardware qualification,
administration), below native Constellation work (U2), and below the stable
application/platform interface work. No current release milestone depends on
graphics.

This note records a direction, not a plan. Where it says "do not decide" or
"do not design", that is the instruction, not a gap to fill.

## What this note is not

The kernel diagnostic console is a separate mechanism. The early
framebuffer/console work needed for boot diagnostics, panic output,
virtual-console visibility, and bare-metal recovery (see "Framebuffer
console" in `docs/DESIGN-INFLUENCES.md`) is not part of the deferred
graphical application/compositor subsystem and is not gated by it.

One requirement flows back from this note to that console: any future
userspace display-ownership design must preserve an emergency diagnostic
path, so the kernel can produce panic and fatal output even if a compositor
owns normal scanout. The exact takeover protocol is not decided here.

## Native direction

If ABSD eventually gains graphics, the preferred native architecture is
layered through userspace services and explicit authority:

```text
display hardware / framebuffer
  -> userspace display service / compositor
  -> surface + buffer capabilities
  -> applications
```

Input follows the same shape:

```text
keyboard / pointing device
  -> userspace input ownership and routing
  -> explicit event delivery / capabilities
  -> selected application
```

The native model should not begin by cloning X11, Wayland, Linux DRM, or
conventional desktop-session assumptions. Compatibility with another graphics
ecosystem may be added later as a userspace layer if a real workload
justifies it (see "Compatibility position").

## Kernel boundary

The kernel should provide only the mechanisms the eventual implementation
actually requires, likely some subset of:

- controlled access to the supported display device
- mapping and sharing of display buffers or memory objects
- device interrupt and event transport
- IPC and channel mechanisms
- explicit authority transfer

Kept out of the kernel, and belonging in userspace:

- windows, placement, focus, z-order, and decorations
- fonts and terminal policy
- desktop and session policy
- application protocol semantics

## Authority model

These are tentative principles for later evaluation, not a specification.

- Applications do not receive ambient access to the display device.
- Applications receive explicit authority to create and use surfaces.
- The compositor owns composition and presentation.
- Keyboard and mouse input is not globally readable merely because a process
  is graphical. Input routing is explicit.
- Focus is a compositor or input-service policy, not kernel magic.
- Graphics authority should remain revocable where the existing authority
  model permits it.

Read, capture, and injection are authorities too, not side effects of being
connected to the compositor. Applications must not receive ambient authority
to modify another client's surface, read another client's surface, capture
arbitrary screen contents, observe global input, or inject synthetic input.
These are modeled as separate explicit authorities where appropriate.
Illustrative future names, not ABI: `SurfaceRead`, `SurfaceWrite`,
`ScreenCaptureGrant`, `InputObserveGrant`, `InputInjectGrant`. Screenshot and
screen-recording ability must not emerge accidentally from compositor
connectivity.

Accessibility remains deferred, but the native model must not make it
structurally impossible. The principle: assistive technology should
eventually receive explicit, reviewable authority to observe or interact with
UI state, rather than depending on ambient cross-client access. No
accessibility API is specified here.

Open question, recorded and not designed: how can an application or operator
distinguish trusted compositor or platform UI from an untrusted client
imitating it? Prior art involving compositor-owned labeling or trusted chrome
should be reviewed before a native protocol is frozen.

Principal question for G2: shared-buffer revocation is explicitly hard.
Revoking authority over a mapped graphics buffer is not assumed to be
equivalent to closing a normal handle. A G2 design must account for the case
where client and compositor map the same buffer, one party's authority is
revoked, the buffer may be actively read for composition or scanout, and
another CPU may hold relevant mappings or TLB state. This may interact with:

- address-space lifecycle
- mapping teardown
- TLB invalidation and shootdown
- compositor ownership
- buffer handoff protocols

This note does not solve it. G2 is intended to expose it, and it is recorded
as one of the principal technical questions of that gate.

Detailed protocol semantics are not frozen.

## Staged progression

If this ever becomes an active lane, use an incremental sequence rather than
designing a mature window system first. Suggested experimental gates:

- **G0:** one known display path shows one CPU-rendered rectangle.
- **G1:** a userspace display owner renders a simple animation to scanout.
- **G2:** two isolated clients submit independent buffers to a userspace
  compositor. This is where shared-buffer revocation is meant to surface.
- **G3:** explicit keyboard and pointer event routing to one selected client.
- **G4:** minimal text rendering, sufficient for a deliberately tiny
  terminal-like program.
- **G5:** only now specify a native surface/window protocol v0, from the
  mechanisms that actually proved necessary.

Do not begin with a general compositor protocol. Let the experiments
determine the minimum stable surface abstraction.

The first native graphical application should be intentionally trivial and
diagnostic rather than respectable (non-normative). A native xeyes-equivalent
is an acceptable cultural target, recast as an authority test. Classic xeyes
demonstrates ambient global pointer observation. The ABSD version should
behave as follows:

- with no pointer-observation grant, there is no global pointer tracking
- with an explicit grant, tracking works
- after revocation, tracking stops

That makes the first graphical application a concrete refusal and revocation
fixture for the graphics authority model, and it validates surfaces,
composition, buffer isolation, and input routing before ABSD pretends to have
a desktop. It may still be ridiculous; that is desirable.

## Initial implementation bias

If ever opened: one exact supported machine and display path; a simple linear
framebuffer or equivalent first; CPU rendering; minimal buffer formats; a
deliberately tiny compositor; bitmap or simple fonts initially.

Explicitly deferred, each possibly earned individually later:

- general GPU acceleration, Vulkan, OpenGL
- Mesa compatibility and DRM compatibility
- arbitrary GPU drivers
- display hotplug and multi-monitor policy
- a HiDPI framework
- sophisticated text shaping
- an accessibility framework
- a desktop shell and window decorations
- a clipboard ecosystem and drag/drop
- remote desktop

## Relationship to the application interface

If the application/platform contract becomes stable before graphics work
begins, graphical primitives should layer on top of that contract rather
than expose raw syscall details. Potential future application concepts,
illustrative only and not in the stable ABI: `DisplayConnection`, `Surface`,
`Buffer`, `InputGrant`, `KeyboardEvent`, `PointerEvent`.

## Compatibility position

Recorded as policy:

> A native ABSD graphics model should be designed around ABSD's authority
> and service boundaries. X11, Wayland, or other compatibility should be
> layered above the native model only when a concrete application gives that
> compatibility work a consumer. Do not reject future compatibility; do not
> let compatibility define the native architecture prematurely.

## Promotion triggers

Promotion from deferred status needs at least one concrete requirement, for
example:

- an application with a real graphical requirement
- an operator workflow materially improved by local graphics
- a supported hardware target whose display path is understood
- U1/U2 maturity sufficiently complete that graphics does not displace
  reliability work
- a legitimate remote-display or evidence-rendering workload

The last one matters because ABSD is likely to be deployed headless or as a
server. A local desktop is not assumed to be the first production consumer.
The same native surface and composition model should ideally stay useful
whether the final presentation target is local scanout, a remote operator
view, or some later compatibility layer. Remote desktop is not implemented
now.

"Operating systems normally have GUIs" is not a trigger.

## Prior art to review before G2 and G5

When the lane is eventually promoted, review small capability-oriented and
userspace compositor systems before freezing the design. This is future lane
preparation, not current work.

- Genode/Nitpicker first: a likely close reference for small trusted
  compositor structure, explicit input routing, client labeling and trusted
  presentation, and capability-oriented GUI boundaries.
- Fuchsia Scenic.
- QNX Screen.
- Redox Orbital.

## Non-goals

- Designing or implementing any of this before promotion.
- Cloning X11, Wayland, Linux DRM, or desktop-session assumptions as the
  native model.
- Treating the kernel diagnostic console as part of this subsystem.
- Putting windows, focus, z-order, fonts, or protocol semantics in the kernel.
- Ambient display, read, capture, input-observe, or input-inject authority.
- Freezing a protocol, an accessibility API, a trusted-path mechanism, or a
  console takeover protocol.
- Any item in the deferred list above, until individually earned.
- Remote desktop now.
- Moving graphics above U1, U2, or the stable application interface work.
