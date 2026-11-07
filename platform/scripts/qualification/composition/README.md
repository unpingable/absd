# Composition subset wrappers

These wrappers preserve the composed qualification sequence and propagate command,
gate, census and leftover failures. They are tracked successors to the reviewed
composition-p15 campaign copies. They report subset execution only. A zero exit
is not full composition qualification; the occurrence intake must verify the
required inventory, actual media result and bound artifact receipts.

Install the original five shell files into a fresh occurrence's `tools` directory. Set
`ABSD_COMPOSITION_PLATFORM`, `ABSD_COMPOSITION_RUN_ROOT`,
`ABSD_COMPOSITION_RUN` and `ABSD_COMPOSITION_KEY` to the admitted worktree,
occurrence, unique run identity and scoped key. The run root must already contain
`logs`, `work/KA`, the occurrence-specific `gate.sh`, `c7.py`, `snapshot.py`,
`verify3.py`, `boot_check.py`, `etc-new` and `etc-c7`. The gate owns current
protected-process identities and load admission; no historical gate is supplied.
Upgrade additionally requires `ABSD_COMPOSITION_LEGACY`; ghost suites require
`ABSD_COMPOSITION_F3_REF`, the admitted source revision containing `qual/blkstall`.
Existing case and ghost directories are refused. Failed work is retained for
inspection; these wrappers never terminate a leftover process.

`must.sh` requires `ABSD_COMPOSITION_MEDIA_STATUS` naming an existing file whose
contents are exactly `PASS` (a terminal newline is accepted by shell substitution).
This is a required occurrence input, not a media oracle: the sealed intake must
independently establish the actual required media execution and result. Missing,
failed or malformed input cannot produce the subset completion message.

Run local command controls with:

```sh
python3 scripts/qualification/composition/test-wrappers.py
```

The controls execute the actual shell wrappers with local command substitutes;
they start no build, guest or remote command. They check propagation, not guest
behavior, media qualification or artifact binding. Temporary fixtures are removed
when the test exits. Keep source and result receipts through integration review;
reproducible local fixture trees have no continuing custody dependency.

Formalization consideration: the proposition is that the enumerated command,
gate, process-census and negative-control failures reach a nonzero top-level exit,
while successful local fixtures remain successful. Practical controls suffice for
this small shell orchestration; this is not a proof for arbitrary shell failures,
concurrent writers or guest behavior. Independent qualification review owns
acceptance of these changed result oracles.

## Final candidate handoffs

Do not reuse the old composition's source pin or its source-specific intake.
Bind the final reviewed source revision, kernel revision, tool identities,
scoped key and lease in the occurrence's existing dispatch. Build the platform
with `ABSD_HTTPS_DOCUMENT=1`, a fresh native document build receipt and
`ABSD_BUILD_RECEIPT` selected for `prepare-and-build.sh`. Retain the C-kit and
ports receipts separately. A and B below are complete release directories;
A is the fixed internal P2 base `03479a3e`, B is the exact candidate bound by that occurrence.
The current provisional A rebuild is `p2-a-03479a3e` (platform
`03479a3e090e847ccdfa647dce44e7b16d035988`); its manifest names kernel
`4bc8009701bfd0ddfde1b27851593aaad9aa906f`. The provisional B build is
`p2-rc-7ed48c21` (platform `7ed48c213e2d2e158329508563fb117fc94651f1`);
its manifest independently names that same 4bc kernel. These refer to fresh
A/B builds, not a rebuild or relabeling of any earlier sealed release.
A is not a published RC1 upgrade claim. These are build identities, not whole-release qualification or
publication: the 7ed preparation failed the shared served-RAM launcher policy
check before ordinary native cases ran. A successor source must be reviewed and
bound in a new occurrence before execution; do not reuse an earlier source's
qualification or silently substitute new pins in a sealed occurrence.

After resource admission, invoke the new handoffs from the exact source
`scripts/qualification/composition/` directory. In particular, keep the Python
helper there so it resolves that source root. The sequence adds these handoffs
to the existing MUST/SHOULD wrappers:

1. Set `ABSD_COMPOSITION_MEDIA_KERNEL` to a fresh dedicated media kernel clone,
   `ABSD_COMPOSITION_KERNEL_COMMIT`, `ABSD_COMPOSITION_QEMU` to an absolute
   admitted executable, and `ABSD_COMPOSITION_BUILD_RECEIPT` plus its independent
   `ABSD_COMPOSITION_BUILD_RECEIPT_SHA256`. `media.sh` invokes the actual
   `qualify-operator-binding.py build`, `boot` and `status`. The status consumer
   checks the exact binding, terminal status, raw console and launch receipt.
   Only then does it create the existing MUST media-status file. The app is
   bound as installed bytes here; its execution belongs to the App A scenario.
2. Preserve the full `vm-operator` profile inventory separately. Set
   `ABSD_COMPOSITION_PROFILE_KERNEL` to another fresh kernel clone and prepare
   the explicit importer handoff below as
   `ABSD_COMPOSITION_PROFILE_BOOT_INPUTS` and its SHA-256. `media-profile.sh`
   runs `media.py operator-image`, `operator-validate`, and the actual
   `test_media.py` against that fixture. It requires exactly
   `MEDIA HOST TEST OK cases=74 skipped=0`. Supply the existing pinned S4 and
   operator reference inputs; a missing fixture is a failed requirement.
   This profile remains its declared default image. Its tests do not execute
   App A or substitute for the separately bound document-enabled media.
3. Set `ABSD_COMPOSITION_P2_A`, `ABSD_COMPOSITION_P2_B`, both independent
   `P2_*_MANIFEST_SHA256` pins, `ABSD_COMPOSITION_SOURCE_REVISION`,
   `ABSD_COMPOSITION_P2_ANCESTRY` and its SHA-256, and
   `ABSD_COMPOSITION_QEMU_SHA256`. `p2.sh` runs the original P00–P08 predicates
   plus the accepted changed-ELF requirement for `tree/bin/https-document`.
   The supplied real QEMU is explicitly rebound inside the runner; exporting
   `ABSD_QEMU` alone never selected release.py's QEMU implementation.
4. Run the existing `release-matrix.py` cases 9 and 13 via
   `recovery-seams.py`. It uses its own fresh work/evidence directories,
   exact manifest/QEMU inputs and bound launches. Both existing case rows and
   the complete launch/catalog inventory are required. Gate and serialize
   this invocation with the occurrence's current `gate.sh`.
5. Run the existing MUST/SHOULD wrappers with their current load/process gate,
   plus the App A replacement producer owned by the application lane. Its
   max-body, receipt, interrupted publication, recovery and new-write checks
   are additional evidence. This producer is not the unfamiliar-operator
   documentation rehearsal.

### Explicit canonical release/importer binding

`release.py` accepts `ABSD_RELEASE_QEMU` for its Boot/importer executable;
its default is unchanged. `operator_image.py` retains its separate `--qemu`
option. For canonical IDE qualification, prepare one input record using the
existing launch adapter module from the exact final source:

```python
from pathlib import Path
import shlex
import sys
import p2_boot_binding

p2_boot_binding.prepare(
    Path(inputs_json), Path(actual_qemu), qemu_sha256,
    [{"path": complete_release_dir, "manifest_sha256": manifest_sha256}],
    Path(fresh_public_launch_receipts),
)
environment["ABSD_P2_BOUND_INPUTS"] = inputs_json
environment["ABSD_RELEASE_QEMU"] = shlex.join([
    sys.executable, str(source_root / "scripts/p2-bound-qemu.py"),
    "-accel", "tcg", "-cpu", "max,vendor=GenuineIntel,+rdrand",
])
environment["ABSD_BLOCK_ATTACH"] = "ata"
environment.pop("ABSD_QEMU_REBOOT", None)
```

The input record verifies admitted manifest pins and their actual SSH/FSD and
importer ELF bytes. Each invocation verifies the actual ISO loader/catalog,
then uses `boot_artifacts.launch` for sealed ISO, inode-pinned writable disk,
paused QMP admission and actual executable/argv checks. The original
`durable-boot.sh`, GNU timeout, process group and exit-status meanings remain
in charge. The adapter inherits their process group and reflects child signal termination.
The deliberate P2 stop targets the actual admitted QEMU child, checked by
serial path, parent PID and start ticks, so killing only the adapter cannot
leave a guest running. The existing `-SIGKILL` oracle is retained. Only the existing
canonical TCG/IDE served and durable steps 1–5 are supported. The new
`-no-shutdown` admission requires its exact `-no-reboot` pair; alternative
boot sources and devices remain refused.

`media.py operator-image` has the explicit `--bound-boot-inputs` and
`--bound-boot-inputs-sha256` pair because its clean environment deliberately
does not inherit arbitrary caller settings. It verifies that the admitted
ELF bundle equals the built platform before passing the adapter to its
canonical producer. `media.py operator-boot` uses the same existing bound
launch and verifies the actual SSH/FSD catalog. Existing media profile
validation, guest command and clean-halt oracles are unchanged.

Retain `UUID.catalog.json`, `UUID.launch.json` and the exact input record.
Call `terminal_bindings(receipts, qemu_sha256, {manifest_sha256})` to reject
missing pairs, non-admission and wrong executable/release pins. The P2
artifact inventory includes these nested files. Preserve independent
terminal workload evidence: launch admission alone is never success.

Required final inventory is the established 31 resume cases; the MUST update
suite and the eight SHOULD suites (matrix, core-fsd, upgrade, ghost-ata,
ghost-nvme, served, survival and link); F2 steps 1–5; both C7 legs; full profile
producer/validation and 74/0
media tests, artifact-bound document-enabled media execution, P2 P00–P08,
realigned release cases 9 and 13, the App A lifecycle/replacement producer,
selected notice closure and public source reconstruction. The unfamiliar
operator rehearsal and any nomination remain separate acceptance steps.
The old historical suite results are not silently promoted to the final
source. Existing regression tools keep their own observations; this adapter
makes no universal QMP-binding claim for ghost/NVMe, historical endurance or
other launch shapes.

Host controls run without builds or guests:

```sh
python3 scripts/test_p2_boot_binding.py
python3 scripts/test_boot_artifacts.py
python3 scripts/test_operator_boot_binding.py
python3 scripts/test-qualify-operator-binding.py
python3 scripts/qualification/composition/test-handoffs.py
```

Formalization consideration: the new proposition is exact active ELF and
ISO/disk/executable input identity for these concrete launch shapes, under
the existing trusted source/compiler/loader and isolated writable-disk
assumptions. Catalog and QMP negative controls, explicit argv/process-group
handoff controls and existing workload oracles are sufficient for this
bounded adapter; they do not prove compiler correctness, bootloader or
firmware correctness, absence of concurrent content mutation outside the
stated descriptor boundary, or native workload success. Root owns independent
review and final qualification acceptance.
