# How a source release is made

ABSD is developed in separate repositories, one per component. This
repository is assembled from them. Its `main` branch moves only when a
release is made, and each release is one commit.

## What a release is

A release is the tree produced by the assembly tool (`tools/assemble.py`,
with `tools/assembly.toml`) from:

- one exact commit of each component, named in `SOURCE-MANIFEST.toml`;
- the list of files left out of each component, also in the manifest;
- the files written for this repository (this file, the top-level README,
  `tools/`, `docs/README.md`).

Nothing else is changed. For each component the manifest records the Git tree
id of its directory here, so anyone can confirm what they have:

    git rev-parse HEAD:kernel        # equals the manifest's kernel `tree`

For `kernel/` and `platform/` it differs from the development commit's tree
only by the excluded files, which are development records (campaign logs,
review transcripts, receipts recorded on the development host) and, in the
platform, the patches and manifests that carry other projects' source for
the extended integration profile.

Assembling the same configuration twice gives the same tree. That is a
statement about source. Whether builds of that source are bit-for-bit
reproducible is a separate question; see the README for what was measured.

## What is checked before a release

The assembly tool reports five things separately and a release needs all of
them:

1. **Pins.** The platform names the kernel and example revisions it was
   qualified against; they must be the revisions assembled.
2. **Private material.** No development-machine paths, host names, private
   addresses or credentials in the tree, apart from findings accepted in the
   configuration with a written reason.
3. **Source readiness.** Each component's own `scripts/provenance.py report
   --require source` must pass: licences, notices and known obligations.
4. **Reproducible assembly.**
5. **Nothing held.** The configuration lists reasons a release is held that
   no check can see; the list must be empty.

Those five say the tree is what it claims to be and safe to publish. They
say nothing about whether it works. That is qualification: the assembled
tree is built, booted and tested from a clean clone in a clean environment,
following only the README. Whatever part of that was not run on a release
is listed in its manifest under `not_run` and at the top of its README, and
is never described as passed.

A tree that has not passed carries a file named `NOT-FOR-PUBLICATION.md`
saying why, from the first moment of its assembly. The tool commits only
the tree its last build produced, and never commits one that has not
passed to `main`.

## Promoting development work

A change reaches a release by being accepted in its component's development
repository under that repository's own checks, and then by a later release
naming a later commit. There is no synchronisation between releases and no
partial update of one file.

Releases are identified by an id in the manifest and a tag of the same name.
Release artifacts are identified by digest; they are not signed.
