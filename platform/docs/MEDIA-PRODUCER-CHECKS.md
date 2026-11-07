# Operator media producer checks

Media and preview producers must run the five `OperatorValidateGrub` cases
against the media they just built and its own platform and kernel trees.
After `media.py operator-image`, use:

```sh
python3 -B scripts/media.py operator-validate --producer-tests \
  --profile vm-operator --platform-tree "$PLATFORM" \
  --kernel-run "$KERNEL" --out "$MEDIA"
```

The command first performs ordinary operator validation. Only after that
succeeds does it run `test_media.py OperatorValidateGrub`. The child receives
`ABSD_REQUIRE_S4=1`, `ABSD_OPERATOR_FIXTURE=$MEDIA`,
`ABSD_OPERATOR_PLATFORM=$PLATFORM` and `ABSD_OPERATOR_KERNEL=$KERNEL` from
these command arguments. Inherited fixture paths are replaced. A fresh
Python cache prefix and disabled bytecode writes keep the test interpreter
from using source-tree bytecode caches.

Success requires child exit zero and the exact five-case, zero-skip terminal
record. The parent then emits:

```text
MEDIA OPERATOR PRODUCER TESTS OK cases=5 skipped=0
```

The producer must stop on a nonzero command result. An ordinary validation
record can exist before these extra cases finish; it does not establish
that producer tests passed. Keep the command log and terminal record with
the run's evidence. The tests copy the fixture before making controlled
changes, and call the validator directly, so this path does not recurse.

`ABSD_REQUIRE_S4=1` is a producer-run requirement for this selected suite.
Do not export it globally to a normal `check-all.sh` run: that gate does not
build the validated vm-operator fixture, so its five skips remain explicit.
The gate, its host pins and its workload are unchanged. This producer check
uses the existing media-host tools and already built media; it adds no
kernel build or guest boot. Calling `operator-validate` without the flag
retains its existing validation behavior.

When adapting a preview producer, add `--producer-tests` to its existing
operator-validate invocation before blanking or any other operation that
changes the bound build trees. Use the same run's media, platform and kernel
arguments. A fixture from another tree must continue to refuse as unbound.
Do not modify a historical producer or relabel a completed run to add this
coverage. Host wiring tests are `python3 -B scripts/test_media_producer.py`;
an actual producer run must establish the five cases on its real fixture.
