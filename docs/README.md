# Documentation

The documents travel with the component they describe. This page says where
to start.

## The system as an operator sees it

- `platform/man/`: the manual pages installed on the image. Start with
  `intro.1`, `afterboot.8`, `handles.7`, `process.7`, `filesystem.7`.
  Rendered at <https://absd.dev/manual/>.
- <https://absd.dev/status/>: what has been qualified, in which environment,
  and what has not. Each release of this repository is described there.

## The kernel

- `kernel/README.md`: what the kernel does and how to build and test it.
- `kernel/HANDOFF.md`: the reference detail: system-call semantics, the
  handle model, memory layout, fault behaviour, known limitations.
- `kernel/docs/USERSPACE.md`, `PROCESS-STARTUP.md`: the system-call interface
  and how a process starts.
- `kernel/docs/HOSTILE-USERSPACE.md`, `ADVERSARIAL-ELF.md`,
  `SYSCALL-DISCLOSURE.md`: what was tried against the kernel boundary, and
  what was not.
- `kernel/docs/BROKER.md`, `NETWORK.md`, `DURABLE-JOURNAL.md`: delegated
  authority, the network device boundary, the durable record.
- `kernel/docs/ARM64.md`: the 64-bit ARM port (virtual machines only).
- `kernel/docs/TERMINOLOGY.md`, `DESIGN-INFLUENCES.md`: vocabulary and
  prior work.

## The platform

- `platform/README.md`: the Rust standard-library port, the runtime, the
  servers, and every check the platform gate runs.
- `platform/docs/FILESYSTEM.md`, `POWER-LOSS.md`: the filesystem format and
  what is claimed about crashes and power loss.
- `platform/docs/RELEASE.md`: release identity, installed generations,
  update and rollback.
- `platform/docs/COMPATIBILITY-LEDGER.md`: how far unmodified Rust programs
  get.
- `platform/PATCH_AUDIT.md`: every change made to the Rust standard library.

## Provenance and licensing

- `SOURCE-MANIFEST.toml`, `THIRD-PARTY.md`, `LICENSING.md` at the top.
- `kernel/docs/PROVENANCE.md`, `platform/docs/PROVENANCE.md`: how
  third-party material and obligations are tracked and checked.

## Planning documents

Some documents under `kernel/docs/` are roadmaps and deferred designs
(`*-ROADMAP.md`, `MATURITY-BACKLOG.md`, `LIVE-EVOLUTION.md`,
`BOUNDED-JUDGMENTS.md`, `GRAPHICS-DIRECTION.md`). They describe intent, not
the system. Nothing in them is implemented unless a document above says so.

Development records (campaign logs, review transcripts, hardware survey
receipts) are not part of a source release.
