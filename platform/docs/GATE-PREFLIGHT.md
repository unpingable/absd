# Gate preflight

`scripts/check-all.sh` first runs `scripts/check-gate-entry.sh`, before source
setup, cleanup traps or builds. It refuses UID zero, checks the commands in
`scripts/gate-host-items.txt`, checks the observed `xfonts-base` package
dependency, and runs the unprivileged namespace probe. Each refusal names the
missing item on one line. The list covers canonical gate commands on supported
hosts; VM provisioning utilities, unused linker aliases, guest commands and
tools generated inside a build venv are excluded. Availability does not replace
the host's pinned package, toolchain-component or provenance checks.

After the first `prepare-and-build.sh`, `check-gate-arity.py` checks the existing
full and core reproducibility hash-list cardinalities against their existing
constants. It reads the literal lists without hashing or building programs.
The real two-build hash comparisons and the declared counts remain unchanged.
Unsupported list syntax is refused rather than guessed.

At the existing C-kit/userland boundary, `check-post-kit.py` checks the original
source, kit and POSIX build receipts and compares `userland/PORTS.tsv` with
`install-userland-ports.sh --print`. The installer receives
`ABSD_PORTS_REQUIRE_BUILT=1`, so a disappearing input cannot start an implicit
build. This check neither installs nor updates a catalog. The later installer
still performs its original context, digest, length, ELF and image checks.
The C-kit build has not moved earlier in the gate.

Independent qualification runners bind their helper cohort after their existing
exact-HEAD and clean-worktree checks, before allocating evidence or starting a
build or guest:

```sh
python3 -B -I "$S/scripts/check-harness-cohort.py" \
    --harness "$H" --harness-rev "$HARNESS" \
    --candidate "$S" --candidate-rev "$PLATFORM" || exit 2
```

The candidate must contain the reviewed checker. Apply this call to the next
unfrozen successor runner; do not edit a sealed historical run or treat an older
product pair as having run it. A chain can call the same host-entry check before
its kernel work. No additional runner, service or scheduling mechanism is needed.

The cohort checker reads pinned Git blobs and follows the local import closure
rooted at `scripts/ssh_absd.py`. It handles ordinary module/package imports and
the script-relative literal importlib loads used by these helpers; unresolved
importlib paths are refused. It reads both sides so a newly local module is
included in the comparison. It refuses Git context overrides and parent-repo
discovery, and disables Git replacement objects on every source read. Local
replacement refs cannot suppress imports from the pinned blobs. It never
imports candidate code. This is source correspondence at
entry, not a lock against concurrent edits or a general Python dependency proof.
The caller's source freeze and normal execution checks remain necessary.

The historical controls include the stale hash counts in candidates 8 and 11,
the stale port catalogs in candidates 7, 8 and 11, and the helper mismatch between
`2f984eb8` and `0fada7ed`. The accepted `cfa5478b` helper cohort matches
`0fada7ed`; it does not automatically match a later candidate. A newly mismatched
cohort needs a separately reviewed source composition. Earlier run verdicts and
the workload classifiers are unchanged.
