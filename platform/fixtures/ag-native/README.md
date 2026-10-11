# AG native path: Linux reference

`reference/i-fresh-ag/` is the run `i-fresh-ag` of
`scripts/make-reference-fixture.sh` (`scripts/reference_fixture.py`; the
other runs of the same production are `fixtures/nightshift-pipeline`, whose
`README-linux.md` describes it). `manifest.json` records every file's
SHA-256, the pinned sources, and the Linux binaries that produced the run;
the matrix runs two of them again (`bin/ag-loopctl`, AG 21c8da0 release
build; `bin/nightshift-observation-resolver`, Nightshift e2675dd release
build, both unpatched) and refuses any drift.

In that run the real Nightshift writer called the real `ag-loopctl init` and
`ag-loopctl record-proposal`; AG's call to the runtime profile's pinned
observation resolver (a wrapper script that execs the real resolver on the
run's store with `--default-ttl-ms 86400000`) answered `current`.
`ag-status.json` is `ag-loopctl status` afterwards; `state/ag.sqlite` is
AG's store and `state/nightshift.sqlite` Nightshift's. The run was produced
at `/tmp/absd-reference/runs/i-fresh-ag` with the wall clock pinned to
2026-10-10T23:43:32Z, so the sealed profile and the store name those paths
and that instant; the matrix's Linux twin mounts the reference there again.

## The issuer key is a test key

`ag/secrets/issuer.pk8` is not a credential and never was one. It is the
Ed25519 key whose 32-byte seed is SHA-256 of the ASCII string

    ABSD test fixture key, not a credential

written as PKCS#8 v2 (the form `ring` reads), with `issuer.pub.der` beside
it; `scripts/reference_fixture.py` derives both. SHA-256 of the raw public
key: `f343565680d785393860dea3c21ec36c72cf81d5c40c2a0ab826bd391497cfe9`.
Anyone can derive the private half, so it must never be enrolled anywhere.
On this path it is a pinned deployment file (measured, never used to sign:
`init` and `record-proposal` reach no issuance), enrolled as
`fixture-ag`/`fixture-key-1` against an empty trust file and a boundary
command that only exits.

It replaced a key that `openssl` had generated at random for the first
reference run. On the development machine that key was found only in that
run, in copies of this fixture and in test images built from it, but
whether it was ever used on another machine could not be established, so it
was retired rather than published.

What the native run takes from here, as opaque bytes: the Nightshift store;
the catalog, Docket trust, boundary command, and issuer key; and the
genesis and proposal documents Nightshift gave AG, read out of the store's
prepared AG request. The runtime profile is sealed again at ABSD paths
(scripts/ag-native-matrix.py), because a profile pins absolute paths and
the resolver's bytes.
