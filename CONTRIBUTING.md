# Contributing

This repository is a source release of ABSD, assembled from the development
repositories at the revisions named in `SOURCE-MANIFEST.toml`. Development
does not happen here. That shapes what happens to a contribution, so it is
stated first.

## What happens to an issue or pull request

1. **Issues** are read here and answered here. A bug report that names the
   release, the host, the command you ran and its output is the most useful
   thing you can send. A failing `tools/check.sh` step, with its log, is a
   complete report.
2. **Pull requests** are read here as proposals. A pull request is never
   merged into this repository directly, because the next release would
   overwrite it.
3. If a change is accepted, the maintainer applies it to the development
   repository of the component it touches (`kernel/`, `platform/`), with you
   recorded as the commit's author and a link back to your pull request. It
   then goes through the same checks as any other change.
4. It appears here in the next source release. The pull request is closed
   with a pointer to that release.

Opening a pull request does not mean it will be accepted, and a merged-looking
state here is not acceptance: acceptance is the change arriving in a release.
You will be told plainly which it is.

## What is easy to accept

- Reproducible failures, with the steps.
- Corrections to documentation and manual pages, especially where a
  statement is stronger than its evidence. An unsupported claim is a bug.
- Small, self-contained fixes with a test that fails without them.

Larger changes (new system calls, new drivers, new subsystems) are unlikely
to be accepted as pull requests. Open an issue first.

## Ground rules for code

- Say where code came from. Do not paste code from other projects, whatever
  their licence, without saying so in the pull request. `THIRD-PARTY.md` and
  each component's `provenance.toml` record everything in this tree that is
  not original to it; a contribution that adds to that list needs its
  upstream, revision and licence stated.
- Do not add licence headers to ABSD's own files; see `LICENSING.md` for why
  there are none yet.
- If an AI system wrote or helped write the change, say so. Most of ABSD was
  written that way and its documents say so; contributions are held to the
  same disclosure.
- Contributions to ABSD's own source are accepted under the Apache License,
  Version 2.0, the licence of the files they change (section 5 of that
  licence applies: what you submit for inclusion is under its terms). By
  opening a pull request you state that you have the right to submit it on
  those terms.
