# App A QEMU VM runner

`scripts/app-a-vm-runner.py` replaces the old App A phase dispatcher. It materializes one exact candidate, stages real media, waits for an exact fresh admission, then runs one bounded outer-VM occurrence. It never retries or resumes an occurrence.

## Offline materialization

```sh
python3 -I -B scripts/app-a-vm-runner.py --materialize \
  --candidate /path/candidate.json \
  --input-root /path/accepted-occurrence-inputs \
  --output-root /path/fresh-output \
  --run 00000000-0000-4000-8000-000000000000
```

The input root supplies the accepted declarative media, guest payload and stage inputs. The candidate supplies `base_source_revision`, `source_revision`, `kernel_revision`, `source_root`, `source_identity`, `driver_source`, `harness_mode`, `payload_pins` and `stage_pins`. Every changed immutable payload or stage member must have an explicit source path, byte count and SHA-256 in the candidate; unchanged members must still match their original pins. `harness_mode` is `app_a` or `smoke_cat`.

The runner observes the clean product Git HEAD and archive identity externally.
The harness revision independently names the clean checkout containing the runner;
it may differ from the product revision. Harness-only fixes can therefore exercise
an unchanged, exactly bound product build without rebuilding it. It does not embed a source SHA in generated source. It seals the config template, payload descriptor, stage manifest and binding manifest in that order, creating first-write parent directories and refusing to reuse an output root.

## Admitted execution

Set `ABSD_APP_A_SSH_TARGET` and `ABSD_APP_A_SSH_IDENTITY` explicitly for the admitted host. There are no lab defaults. The runner disables SSH agents and forwarding, uses only the named identity, and retains batch mode and strict host-key checks. These inputs do not grant execution authority.

```sh
python3 -I -B scripts/app-a-vm-runner.py --execute \
  --candidate /path/candidate.json \
  --admission /path/fresh-admission.json \
  --input-root /path/accepted-occurrence-inputs \
  --output-root /path/fresh-output \
  --run 00000000-0000-4000-8000-000000000000 \
  --control-port 24131 \
  --qemu-python /path/qemu-8.2.2/python \
  --harness-revision 0123456789abcdef0123456789abcdef01234567
```

After media staging, the runner writes `ADMISSION-REQUEST.json` and waits for the admission file. Admission must name the same run and materialization SHA, a fresh resource sample and launch window, and the unchanged 14,400-second outer contract. The VM is not launched without it. One staging_host `systemd` unit owns the remaining sequence, and the staged executor uses the dispatch's absolute time bounds.

The pinned QEMU helper first passes a real `-machine none` launch/QMP/shutdown probe. The same adapter then launches the outer VM. Before invoking the first guest phase,
it mounts the `ABSDINPUT` ISO read-only at `/mnt/input` and verifies its manifest
and member hashes against the staged identity. Smoke runs the existing install/boot path and `/bin/cat` in the nested ABSD guest, producing `SMOKE_PASS_NOT_QUALIFICATION`; it is not App A qualification. App A uses the existing six-case product oracle unchanged.

QEMU's `-pidfile` supplies the emulator PID in the container's PID namespace.
The Python helper's process PID belongs to its launch wrapper and must not be
used to signal the emulator inside the container. QEMU 8.2.2 has no `query-pid`
QMP command.

Before staging a smoke, run the local harness suite with the pinned helper tree:

```sh
ABSD_QEMU_PYTHON=/path/qemu-8.2.2/python python3 -B scripts/test_app_a_vm_runner.py
```

The production-launch regression uses the installed emulator with `-machine
none`, exercises both launch paths behind a separate wrapper process, and checks
the actual emulator PID. It requires local Unix sockets and a temporary loopback
listener. Guest identity and SSH are fixtures in this test; it does not establish
guest boot or smoke success. A skipped real-emulator test leaves that boundary
unverified.

`RESULT.json` distinguishes harness incompleteness from a genuine product `FAIL`. The runner creates the shared clock-output parent before invoking the helper,
which owns each fresh phase directory. On a failure before the product starts,
evidence export preserves whichever guest evidence/public directories exist.
Public evidence is archived before exact-key and overlay teardown. The staging_host staging root and evidence disk remain explicitly retained for build_host custody until independent review and the recorded closeout; they are not silently deleted or called absent.

## Pinned runtime dependency

The VM lifecycle uses QEMU's own Python `QEMUMachine` and QMP helpers, not ABSD lifecycle machinery. The qualification input is QEMU `v8.2.2`, commit `11aa0b1ff115b86160c4d37e7c37e6a6b13b77ea`:

- Archive: `https://github.com/qemu/qemu/archive/refs/tags/v8.2.2.tar.gz`
- Archive SHA-256: `6a3147de6c3158086d220cd2b3b01636238913c60cfdf3047ffdcfe47124c54a`
- `qemu.machine` and legacy QMP wrapper: GPL-2.0-only
- `qemu.machine.console_socket`: GPL-2.0-or-later
- `qemu.qmp`: LGPL-2.0-or-later

The upstream package is staged as a separate qualification dependency with its license texts; it is not vendored into ABSD source or the operator image. QEMU's helper API is pinned rather than treated as a stable external interface. The existing `served_qemu` RAM policy remains mandatory.

The materializer binds the pinned PKI fixture producer to the verified product
revision before sealing the payload and delivery manifest. Its historical source
file stays immutable. The runtime binder still requires the resulting lifecycle
intent to match the selected product source and exact leaf-key path.

The P2 importer adapter supports the driver's isolated Python invocation (`-I`).
It explicitly loads its adjacent repository modules; it does not depend on the
current directory or `PYTHONPATH`. Its subprocess regression exercises the actual
adapter through its bound-input validation without starting QEMU.

App A cleanup stops QEMU and retires the outer transport key but retains
`root.qcow2` and its exact `base.img` backing dependency. Failed target images,
the recovery point, and VM-local credentials remain in that stopped VM under
the configured custodian and retirement condition recorded in `CLOSEOUT.json`.
A PASS or missing driver result never authorizes their deletion. Resolve those
dependencies before retiring staging; public evidence export excludes private
artifacts. Only a passing smoke with successful evidence export retires its
overlay after QEMU stops. Failed smoke overlays retain diagnostic dependencies.
Failed preparation phases export their exact unit journal before cleanup; a
journal retrieval failure preserves the primary error and is recorded in closeout.

Payload rows delivered under the protected platform checkout are materialized
from the selected Git commit, so their bytes match the separately cloned source.
Conflicting explicit payload pins are refused. Historical input files remain
immutable, and the fresh copies enter the normal delivery and payload seals.

Before QMP quit, cleanup requests `sync -f / /evidence` inside the outer guest
with a bounded timeout and records the result. Failure retains the overlay and
backing image, reports incomplete cleanup, and still proceeds with bounded QEMU
termination. A successful flush is not a claim of clean filesystem unmount.
