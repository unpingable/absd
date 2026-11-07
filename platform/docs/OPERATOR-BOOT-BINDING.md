# Operator boot artifact qualification

`scripts/qualify-operator-binding.py` qualifies one exact operator-media
construction and execution. It does not nominate a release or qualify every
historical matrix boot. The ordinary operator producer and filesystem reader
remain `operator_image.py`; the kernel and stored formats are unchanged.

Build the clean platform with `ABSD_PROFILE=core` and `ABSD_BUILD_RECEIPT`
pointing to a fresh receipt outside the source tree. Run the usual C-kit/ports
build with its existing input/provenance checks. The opt-in receipt binds the
nonincremental successful `prepare-and-build.sh` invocation, clean source
samples, producer tool hashes and freshly produced ELF/command bytes. A failed
build leaves only a pending record. Shared compiler libraries, toolchain
correctness and transient concurrent source writers are outside this receipt;
the occurrence must have exclusive source/build ownership.

Use a fresh disposable kernel checkout with no `build/`, and an occurrence SSH
key under the campaign's existing credential and resource rules. Example
(`QEMU` must be an absolute executable, not a command string):

```sh
python3 -I scripts/qualify-operator-binding.py build \
  --kernel "$KERNEL" --kernel-commit "$KERNEL_COMMIT" \
  --out "$MEDIA" --qemu "$QEMU" --authorized-keys "$KEY.pub" \
  --build-receipt "$BUILD_RECEIPT" --build-receipt-sha256 "$BUILD_SHA256"
python3 -I scripts/qualify-operator-binding.py boot \
  --kernel "$KERNEL" --out "$MEDIA" --qemu "$QEMU" \
  --build-receipt "$BUILD_RECEIPT" --build-receipt-sha256 "$BUILD_SHA256" \
  --binding-sha256 "$BINDING_SHA256" --login-key "$KEY" --results "$RESULTS"
```

The caller pins the receipts' actual SHA256 values before boot; merely finding a
file with the expected name is insufficient. Build invokes the canonical
operator producer, verifies the source before and after kernel construction,
checks the actual ISO kernel/configuration and its unique complete program
catalog, and compares disk commands to the produced platform outputs. The
catalog check follows pointer/length pairs into file-backed ELF load segments,
not arbitrary byte occurrences. Unexpected catalog layouts refuse.

Boot rechecks that chain. It copies the disk to a private occurrence path and
copies the admitted ISO to a sealed Linux memfd. QEMU starts paused with explicit
ISO boot order. Before `cont`, QMP's inserted block devices, `/proc` executable,
argv, process start identity and input descriptors must match the expected
bytes and inodes. Alternate boot sources and extra disks refuse. The writable
disk remains inode-pinned; its contents require exclusive occurrence ownership.
The admission record is flushed before releasing the guest CPU.

Qualification then requires the existing SSH readiness protocol, strict host
key verification from that boot's console, successful hash and command sessions,
and clean shutdown. The host independently checks the selected on-disk command
bytes before and after execution. The mutated disk copy (including its generated
host key) is deleted; its digest, serial, launch and terminal records remain.
`LAUNCH.json` alone is not execution success: require `RESULT.json` passed,
QEMU status 3, its bound serial/session evidence and unchanged executed files.

The execution claim assumes the reviewed kernel/init/filesystem/ELF-loader and
compiler semantics. It establishes exact artifacts and observed execution of
the bound service/command path, not instruction-by-instruction measurement or
remote attestation. Firmware and QEMU correctness are trusted. It does not
transfer this result to different media, later source, other controllers or
the old 31-case/eight-suite occurrence. C ports use their separate existing
provenance records; this receipt does not claim fresh recompilation of them.

Formalization consideration: the durable proposition is that admission must
refuse a disagreement at any checked source/output/media/catalog/open-input
boundary, before CPU continuation. Positive and negative controls exercise
those boundaries; sealed ISO descriptors eliminate pathname/content replacement
after admission for that input. Writable-disk concurrency, compiler semantics
and the correspondence from the catalog to loader execution remain explicit
assumptions, not a proved general state-transition theorem. Independent review
adjudicates the resulting bounded claim and actual execution evidence.
