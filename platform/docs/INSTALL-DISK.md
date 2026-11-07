# Installing ABSD onto a GPT disk (coordination record #123, step 5)

For the software-only ABSD writer that reuses this layout and ESP builder,
see [Native installer](NATIVE-INSTALLER.md).

`scripts/install_disk.py` makes one disk that a machine's UEFI firmware
boots and ABSD stores its data on. It is a host tool. In this slice it
installs onto **disk image files only**. A block device takes the same code
path as far as the target check, and is then refused (see "Block devices").

```
install_disk.py identity --target IMAGE
install_disk.py install  --target IMAGE --kernel KERNEL.ELF --serial SERIAL --receipt NEW.json
                         [--boot-options "durable=0 net fsd served"] [--kernel-sha256 HEX]
                         [--manifest MANIFEST] [--confirm-disk TOKEN]
install_disk.py verify   --target IMAGE [--receipt RECEIPT.json] [--outside-unchanged]
```

Exit statuses:

| exit | meaning | target | receipt |
|---|---|---|---|
| 0 | installed and verified | the new disk | `absd-disk-install-receipt/1` |
| 2 | refused before the first write (`INSTALL REFUSED <reason>`) | unchanged | none |
| 3 | failed after the first write (`INSTALL FAILED step=<step> ...`) | written, inside the install regions only; not a valid ABSD disk | `absd-disk-install-failure/1` at `--receipt`, or on stdout if that cannot be written |

Every refusal is decided before anything is written to the target. That
includes a preflight of everything the success receipt needs:
* every tool, including `git` (the installer's revision) and `dpkg-query`;
* the installer's revision itself, the package versions, `sgdisk
  --version` and the profile digest, all collected up front;
* the receipt destination: no file at the path, and a directory that
  exists, is writable, and has at least 4 MiB free.

If the first write step itself fails, the installer checks the content
digest of both install regions. If they are unchanged it still reports
exit 2.

From the first change to the target until the success receipt is synced
on disk, any failure is exit 3. That covers writing, read-back, building
the receipt and writing it (see "Failures after the first write"). Exit 0
is decided only once the success receipt has been written and synced.

### Output is best effort; the exit status and the receipt are the record

The outcome is decided first, and reporting cannot change it. Every line
on stdout or stderr goes through one emitter that never raises. A write or
flush that fails (EPIPE/BrokenPipeError, any OSError, or ValueError on a
closed stream) silences that stream for the rest of the run: as a best
effort, its file descriptor is pointed at `/dev/null`, following Python's
documented idiom for SIGPIPE. That can itself fail (no descriptor left to
open `/dev/null`), so the status is finally preserved by `os._exit`, below,
not by the silencing.

* `INSTALL OK ...` on stdout is best effort. A reader that has gone away
  does not change exit 0. **The success receipt is the record of an
  install, not stdout.**
* `VERIFY OK` and the `identity` JSON are also best effort. Their exit
  status is decided by the checks.
* The tools that run before the first write while building the ESP print
  nothing on success. grub-mkstandalone and mkfs.vfat run with their
  output captured.

**Order after a write failure:**
1. stderr: `INSTALL FAILED step=<step> <error>; target <path> was written,
   only in byte ranges <regions>; ...`. This comes before any receipt
   attempt.
2. The failure receipt at `--receipt`.
3. If that fails, stderr says so, and the failure receipt goes to stdout
   after `INSTALL FAILURE RECEIPT`.
4. If stdout fails as well, stderr says that too, when stderr still works.
5. Last, on stderr, where the failure receipt went (path, `stdout`, or
   `lost (stdout failed)`), the target and its ranges again, and any
   `residual_receipt` notes.

If stderr is broken, the receipt file or stdout carries the target and its
ranges. If all three are gone, exit 3 is still the status.

## The layout

The disk uses 512-byte sectors and a standard full-disk GPT. It has a
protective MBR, a primary GPT at LBA 1-33 and a backup GPT, written by
`sgdisk` (gdisk). The backup header is the device's last LBA and its
128-entry array is the 32 sectors right before it.

| # | what | first LBA | sectors | size | type GUID | name |
|---|---|---|---|---|---|---|
| 1 | EFI System Partition, FAT32 | 2048 | 524,288 | 256 MiB | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | `EFI System` |
| 2 | ABSD partition, left zero | 526,336 | 4,194,304 | 2 GiB | `7AF614A7-2C5B-4EBA-B8F6-217AEC90357A` | `ABSD` |
| - | unallocated | 4,720,640 | to the backup GPT | rest of the disk | - | - |

Both partitions start on a 1 MiB boundary. The smallest disk the
installer accepts is 4,720,673 sectors: the two partitions plus the
backup GPT. The rest of a larger disk stays unallocated, and v0 has no
option to use it and no dual boot.

* **ESP, 256 MiB.** This is FAT32 with 512-byte clusters (`mkfs.vfat -F 32
  -s 1`), about 520,000 clusters. That is well above FAT32's 65,525-cluster
  minimum, so no firmware sees FAT16. The boot files use about 3 MiB. The
  extra space leaves room for later kernels, and 256 MiB is a size the
  firmware of common machines handles. The volume serial is random for
  each install.
* **ABSD, 2 GiB.** This is the measured size. Under layout v3 the
  filesystem region is the second half of the device, so a 2 GiB partition
  gives the 1 GiB filesystem region that docs/storage-sizing-20261102/RESULTS.md
  recommends. The installer does not format it, because the guest's first
  writable mount runs `Layout::format`, which requires the device to read
  as zeros. The installer checks that all 2 GiB read as zero after it has
  finished.

## GUID policy

* The **type** GUID of the ABSD partition is fixed:
  `7AF614A7-2C5B-4EBA-B8F6-217AEC90357A`. It was newly generated (UUIDv4)
  for ABSD and is not the Linux, FreeBSD or Microsoft type.
* The disk GUID, the ESP's unique GUID and the ABSD partition's **unique**
  GUID are fresh random UUIDv4s for every install. They are never derived,
  reused or accepted from the caller. They appear in the receipt, in
  `INSTALL.JSON` on the ESP, and in the `INSTALL OK` line.
* The kernel selects the partition by its unique GUID
  (`block-partition=<unique GUID>`), never by its type. Identity and type
  stay separate: a second ABSD disk in the same machine has the same type
  but another unique GUID.

## Boot files on the ESP

```
EFI/BOOT/BOOTX64.EFI   grub-mkstandalone x86_64-efi; finds this FAT by its serial,
                       then reads /BOOT/GRUB.CFG
BOOT/KERNEL.ELF        the --kernel input (must pass grub-file --is-x86-multiboot2)
BOOT/GRUB.CFG          one entry: multiboot2 /BOOT/KERNEL.ELF <options>
                       block-partition=<unique GUID> ahci-write=<serial>
INSTALL.JSON           the GUIDs, type, serial, kernel digest and kernel line
```

`--boot-options` defaults to `durable=0 net fsd served`. That is the
served boot the operator ISO's GRUB entry uses (media/vm-operator.toml),
with its disk selection replaced by the installer's own. The kernel to
pass is that ISO's `/boot/absd-kernel`: the served kernel, which embeds
the file server and sshd. Pass its `MANIFEST` with `--manifest`, and its
digest with `--kernel-sha256` to pin it. The installer sets the disk
options itself and refuses any of `block-partition=`, `ahci-write=`,
`ahci-disk=`, `nvme-write=` or `nvme-disk=` in `--boot-options`.

`--serial` is the IDENTIFY serial that the target disk will present to
the AHCI driver. It is 1-20 characters from `A-Z a-z 0-9 . _ -`, because
a boot option cannot carry spaces. A real disk whose serial has inner
spaces needs a kernel-side spelling rule first.

The tool versions are pinned in media/disk-install.toml (gdisk,
dosfstools, mtools, grub-common, grub-efi-amd64-bin). They are checked
before the target is opened. Every program runs by absolute path from its
dpkg package with media.py's clean environment (`media.tool`,
`media.clean_env`).

The ESP is built whole in a private 256 MiB image file in a fresh
temporary directory, never on the target:
* `mkfs.vfat -h 2048`, so the hidden-sector count is the partition's first
  LBA;
* the files are copied one at a time in sorted order and their directory
  dates are normalised (`media.fat_copy`, `media.normalize_fat_dates`);
* `GRUB.CFG` is read back with `mtype`.

That image's data extents are then written into the target at the ESP's
offset. The installer then checks that the target's ESP range hashes to
the image's. The install is not meant to be
byte-reproducible, because its GUIDs and FAT serial are random. The
receipt records everything else.

## Binding to the validated target

The target is opened once and then held:
* It is opened with `O_NOFOLLOW` (and `O_NONBLOCK`, so a FIFO swapped in
  cannot block the open). The file must be regular, with the same device
  and inode numbers as the pathname's `lstat`.
* It is held under an exclusive `flock` for the whole install. A second
  installer, or a `verify`/`identity`, finds the lock and is refused
  (`target_busy`).

**Prerequisite: exclusive use.** The flock is advisory. It stops only
programs that also take it. During an install nothing else may write the
target: no mounted loop device, no VM using the image, no other tool. The
installer cannot detect or stop a non-cooperating writer. The checks below
catch the object being replaced, relinked, resized or changing type. They
do not catch another process rewriting bytes of the same file in place at
the same size during the writes. The only content check is the one made
before the first write: identity, emptiness and, when confirming, the
token's digests, recomputed on the locked descriptor. After that,
the read-back checks the GPT, the ESP's SHA-256 and the ABSD partition's
zeros, but not the unallocated span or bytes outside the regions.

Every write goes through that descriptor:
* hole punching uses `fallocate(PUNCH_HOLE|KEEP_SIZE)` on the descriptor;
* the ESP is copied with `pwrite` on the descriptor;
* sgdisk runs on `/dev/fd/N`, the descriptor passed with `pass_fds`, never
  on the pathname. sgdisk is the only tool that touches the target.
  `sgdisk --verify` reads it the same way.

The same checks run in several places: before the first write, after each
write step, and after the read-back. Each time, the descriptor's
`fstat` must still be a regular file with the same device, inode and size.
The pathname's `lstat` must still name that file and must not be a link.
Before the first write the installer also recomputes the target's identity
and emptiness on the locked descriptor. They must equal what was inspected,
or must match the confirmation token if one was given. A file swapped at
the path, or a link to a device swapped in, is then refused with exit 2 and
nothing written, and the replacement is never opened for writing. A swap
after the first write fails with exit 3. The writes went to the validated
file, and the replacement is still untouched.

## What the installer writes, and what it refuses

The installer writes only two byte ranges, the **install regions**:

* the head, from byte 0 to the end of the ABSD partition: the MBR, the
  primary GPT, the gap up to LBA 2048, the ESP and the ABSD partition
  (which stays zero);
* the tail, the last 33 sectors: the backup GPT.

`install` never writes between the end of the ABSD partition and the
backup GPT (the **unallocated span**). It reads that span only to record
the baseline for `verify --outside-unchanged`. The host tests check this
with marker bytes.

**A target is empty** when it has no MBR or GPT signature and every byte
of both install regions is zero. The signatures checked are `55AA` at byte
510, and `EFI PART` at byte 512 or 4096 or in the last 512 or 4096 bytes.
On a sparse image only the allocated extents are read (SEEK_DATA); a
hole reads as zero.

**A target that is not empty is refused**, with every reason listed, its
size and the SHA-256 of its first MiB. Examples are an existing GPT or MBR,
a previous install, or one stray byte in the ESP's range. Nothing is
written. The refusal does not print a ready-made confirmation.

**Other refusals** are made before anything is written:
* a target that does not exist (create the image first, e.g. `truncate -s`);
* a link;
* anything other than a regular file;
* a size that is not a multiple of 512, or is below the minimum;
* an existing receipt path;
* a kernel that is not multiboot2, or that does not match `--kernel-sha256`;
* a malformed serial or boot option;
* unpinned tool versions;
* a target locked by another installer;
* a target replaced, relinked or changed between inspection and the first
  write (`target_changed`).


The process ends through `finish(code)`: a last best-effort flush, then
`os._exit(code)`, which skips the interpreter's own exit-time flush. That
flush could otherwise still fail (EPIPE on a broken pipe, or EBADF when no
`/dev/null` could be opened to silence a broken stream, for instance under
descriptor exhaustion) and turn the status into 120. By then the target is
closed, the removal of staging has been attempted (a failure is reported
as `INSTALL CLEANUP FAILED staging=…` and can leave files behind) and any
receipt is fsynced, so nothing installer-owned is left to run at exit;
`atexit` handlers are skipped. The exit status is exactly the decided one
whenever `cli()` returns. Cancellation or a killed process are outside
this guarantee.

### Exact-disk confirmation

Overwriting a target that is not empty needs `--confirm-disk TOKEN`, where
TOKEN names **this exact disk** and its current contents:

```
image:path=<realpath>,dev=<st_dev>,ino=<st_ino>,bytes=<size>,first-mib-sha256=<hex>,regions-sha256=<hex>
```

"Exact" means every field equals the target's, recomputed on the locked
descriptor immediately before the first write:

| field | what it is | what it rules out |
|---|---|---|
| `path` | the target's `realpath` (links are refused anyway) | a copy at another path |
| `dev`, `ino` | the open file's device and inode numbers | another file at the same path, even a byte-identical one |
| `bytes` | the size to the byte | a size off by one |
| `first-mib-sha256` | the SHA-256 of bytes 0..1 MiB (MBR, both 512- and 4096-sector GPT headers and their entries) | a changed partition table |
| `regions-sha256` | the content digest of both install regions, i.e. everything install would erase | a change anywhere in what install would erase |

The content digest is SHA-256 over (offset, length, bytes) of every
1 MiB-aligned window of the regions that holds a non-zero byte. Equal
bytes give an equal digest whether zeros are holes or written zeros, so it
is cheap on sparse images.

Any mismatch is refused by name (`confirm_mismatch path|dev|ino|bytes|first_mib_sha256|regions_sha256`),
with nothing written. So is a token that is malformed, has a field missing
or repeated, has upper-case hex, or is the `device:` form.

`install_disk.py identity --target IMAGE` prints the target's identity,
why it is not empty, and its token. Getting a token is a deliberate
second step: someone has to inspect the disk to obtain one. A token is
spent by its use, because a successful install rewrites the first MiB and
the regions.

With a valid confirmation, the installer punches holes over both install
regions through the descriptor and reads them back as zero. It then
installs as on an empty target. Bytes outside the regions are kept. The
receipt records `was_empty: false`, the reasons and the token used.

For a block device (not implemented), the token would replace path, dev
and ino with the IDENTIFY serial (`device:serial=...,bytes=<BLKGETSIZE64>,...`).
It is parsed and refused today.

## Failures after the first write

Exit 3 means the target was written and is not a valid ABSD disk. The
write steps are, in order:
* `zero-regions` (only for a confirmed overwrite);
* `gpt` (sgdisk);
* `esp` (the copy);
* `readback`.

The last step, `receipt`, builds the success receipt and writes it. A
failure in any step writes `absd-disk-install-failure/1` to the
`--receipt` path. That covers a failed descriptor/pathname check after a
step, an I/O error, and anything else raised while building or writing the
receipt. The receipt is written to a new file and synced. If that write
fails (ENOSPC, EIO), the half-written file is removed. The only exception
is when the removal fails too. Then the truncated file stays, and it is
named with a `residual_receipt: <path> (truncated, remove it; ...)` note.
The note goes on stderr and into the failure receipt's `residual_receipt`
list. The original write error is the one reported in the `INSTALL
FAILED` line, and the removal's error appears only in the note. The
failure receipt records:
* the target's identity before the first write (path, dev, ino, bytes and
  both digests);
* `write_regions`, the only ranges that can have changed;
* `steps_completed`;
* `failed_step` and the error;
* the GUIDs it was installing;
* the recovery text.

If the failure receipt cannot be written either, it is printed to stdout
after a line `INSTALL FAILURE RECEIPT`. In every exit-3 case stderr
carries one line naming the failed step, the error, the target's path and
the written byte ranges, and where the failure receipt went.

Cleanup never changes the outcome. This covers closing the target
descriptor and removing the staging directory (`install`), and closing
the descriptor (`verify`, `identity`). A failure there is reported as its
own line, `INSTALL CLEANUP FAILED target-fd=<path>|staging=<path>
error=<error>`. The exit status stays the one the install decided: 0, 2
or 3. The receipts are already written by then, so the cleanup line
appears only on stderr.

**Recovery:** do not boot the target. Bytes outside `write_regions` were
not written by the installer. To retry on the same target:
1. Run `install_disk.py identity --target T`. It reports the partial
   writes and a new token.
2. Run `install --confirm-disk <that token>` with a new receipt path. This
   zeroes both regions and installs.

An image can instead be deleted and recreated. The host tests run this
recovery after simulated failures after the gpt and esp steps. They also
check that:
* a receipt-building failure after the writes is exit 3;
* an ENOSPC on the receipt write leaves a failure receipt;
* a persistent EIO leaves no file and prints the failure receipt to stdout.

## Read-back

After writing, `install` checks the result. `verify` repeats the same
checks on an existing image at any later time, and refuses anything that
is not exactly this layout. It never repairs anything.

* **sgdisk:** `sgdisk --verify` must report `No problems found`.
* **Protective MBR:** one record of type `0xEE` from LBA 1 over
  min(last LBA, 2^32-1) sectors, status 0, records 2-4 empty, `55AA`.
* **Primary and backup headers:** each has the signature, revision 1.0, a
  92-byte header, a valid header CRC, and zero reserved bytes and sector
  tail.
  * MyLBA, AlternateLBA and the entries LBA must be 1/last/2 for the
    primary and last/1/last-32 for the backup.
  * There must be 128 entries of 128 bytes, with the usable range
    34..last-33.
* **Entry arrays:** both arrays have a valid CRC, and they are
  byte-identical. Both headers agree on the disk GUID, the usable range
  and the array CRC.
* **Partitions:** exactly two used entries, with the types, ranges and
  names above, no attributes, and every unused entry all zero. The disk
  GUID and the two unique GUIDs are distinct and non-zero. With a
  receipt, the GUIDs must be the receipt's.
* **Partition contents:** after `install` only, the ABSD partition reads
  as zero, the target's ESP range has the ESP image's SHA-256, and its
  boot sector is FAT32 with the receipt's serial. `GRUB.CFG` was read back
  from the image before it was copied.
* **`verify --outside-unchanged`:** every byte of the target outside the
  ABSD partition is compared with the receipt's baseline:
  * LBA 0-2047, the ESP and the backup GPT's 33 sectors by SHA-256;
  * the unallocated span:
    * if it was all zero at install, it must still read all zero. Only its
      data extents are read (SEEK_DATA/SEEK_HOLE), and the whole span is
      read where the filesystem cannot report holes;
    * otherwise its content digest must equal the receipt's.

  Use this after any guest boot to show that the guest wrote nothing but
  its partition. The ABSD partition itself is not compared.

The host tests corrupt each of these and check that the read-back refuses
it.

## The receipt

The receipt is JSON (`absd-disk-install-receipt/1`), written with
exclusive create after everything has verified. It holds:
* **target:** the resolved path, dev, ino, bytes, sectors, `was_empty`,
  the reasons, the confirmation token, and the first-MiB and regions
  digests before the install;
* **inputs:** the kernel's digest and size, the serial, the boot options
  and the manifest digest;
* **GUIDs and types;**
* **layout:** first LBA, sectors, byte offset and length of both
  partitions, the unallocated LBA span, the backup GPT's LBAs and the
  install regions;
* **ESP:** the FAT serial and label, every file's digest and the copy
  order;
* **GRUB:** the kernel line, the whole `GRUB.CFG` and the module list;
* **outside baseline:** the SHA-256 of the head, the ESP and the backup
  GPT, and the unallocated span's range, `all_zero` and (if not zero) its
  content digest;
* **steps:** the write steps completed;
* **read-back:** the sgdisk verify text, both headers as parsed and the
  partition entries;
* **tools:** the pinned package versions checked, all package versions,
  `sgdisk --version`, every tool's path and digest, and the environment.

## Block devices

Block devices are refused in this slice. When the pathname's `lstat`
shows `S_ISBLK`, the installer refuses before opening it, with or without
`--allow-block-device` (that flag is also refused). A link is refused
outright, and a device swapped in later fails the descriptor/pathname
checks. The same code path would serve a device:
* the descriptor;
* the regions;
* the empty check;
* the token;
* sgdisk on `/dev/fd/N`;
* the ESP copied by `pwrite`;
* the read-back. A hardware session will additionally need:

* **Device identity:**
  * the IDENTIFY serial, read from the device itself and matched against
    `--serial`, and used in the `device:` token;
  * the size from `BLKGETSIZE64`;
  * a logical sector size of 512 (refuse 4Kn).
* **Exclusive use:** open with `O_EXCL`; refuse a device that is mounted,
  holds a mounted partition, or is in use by md, dm or LVM; refuse the
  disk the host itself boots from.
* **Zeroing instead of hole punching.** The ABSD partition must read as
  zero. TRIM alone does not guarantee that a later read returns zeros
  (that depends on the drive's DRAT/RZAT). A device install would zero the
  2 GiB partition and the tail with `blkdiscard --zeroout`, or by writing
  zeros, then read both back. The 256 MiB ESP is rewritten by mkfs.vfat.
* **After writing:** flush (`fsync`, `BLKFLSBUF`), then ask the host kernel
  to reread the partition table (`BLKRRPART`).
* **On the target:** IOMMU containment on the target platform before any
  writable boot of a physical disk (coordination record #111), and the machine's
  firmware and Secure Boot posture, recorded by the operator. GRUB here is
  unsigned.

## Evidence

The host tests are `scripts/test_install_disk.py`, which `check-all.sh`
runs. They use sparse 3 GiB images in a temporary directory:
* the layout and both copies;
* bytes outside the regions never written;
* fresh GUIDs on every install, and odd sizes;
* `verify --outside-unchanged`: a byte changed in the head, the ESP, or the
  start, middle or end of the unallocated span is caught, and a span that
  held data is checked by its digest; a write inside the ABSD partition is
  not reported;
* the binding to the validated target:
  * a file swapped at the path between inspection and writing is refused
    with exit 2, with both files unchanged;
  * a link to a device (standing in for a block device) swapped in is
    refused, and no tool ever receives the pathname;
  * a swap after the first write fails with exit 3, with the replacement
    untouched;
  * a held lock is refused;
* failures after the gpt and esp steps: exit 3, the failure receipt, and
  the documented recovery;
* preflight before any write: a missing `git`, and a receipt directory that
  is missing, read-only or full, each give exit 2 with the target
  unchanged;
* after the writes: a metadata failure, an ENOSPC on the receipt write
  (failure receipt left) and a persistent EIO (failure receipt on stdout)
  each give exit 3 with the target and its regions named on stderr;
* cleanup:
  * writes done, receipt ENOSPC, failure receipt written, then a staging
    cleanup EIO: still exit 3, with the target, the regions and the
    cleanup line on stderr;
  * the same cleanup EIO leaves exit 0 and exit 2 unchanged;
  * a failing descriptor close is reported and the install still exits 0;
* a receipt write EIO after 100 bytes, then an unlink EIO: exit 3, the
  write error first, and the truncated file named as `residual_receipt` on
  stderr and in the failure receipt printed to stdout;
* broken output, in process: every path after the first write is run with
  stdout broken, stderr broken and both broken (EPIPE on every write and
  flush). The paths are:
  * success;
  * a failure after the gpt step;
  * receipt ENOSPC once;
  * receipt EIO, so the failure receipt goes to stdout;
  * receipt EIO followed by an unlink EIO (residual receipt);
  * receipt ENOSPC followed by a staging-cleanup EIO;
  * plus a refusal, `verify` and `identity`.

  In every case the status is the decided one (0, 2 or 3). When stderr
  works, its first line names the target and its ranges. Any receipt left
  on disk parses as complete;
* the real CLI in a subprocess, with stdout (and stderr) on a pipe whose
  read end is closed, so the interpreter's exit flush is covered too:
  * success with stdout closed, and with both closed, exits 0 with a
    complete receipt and no "Exception ignored";
  * receipt EIO with stdout, stderr or both closed exits 3, and the
    target and its ranges are named whenever stderr works;
  * `verify` and `identity` with stdout closed exit 0;
  * a refusal with both closed exits 2.

  The installer before this change exited 120 on the success case.
* refusals of an existing GPT, an MBR-only disk, one non-zero byte in each
  region, an installed disk, bad targets, options, kernel, receipt and a
  (faked) block device, each with the target's bytes unchanged;
* the exact-disk confirmation:
  * the right token is accepted;
  * refused: size ±1, a wrong dev, ino, first-MiB or regions digest, a
    wrong path, a twin disk, and malformed tokens;
  * refused: the token reused on a byte-identical replacement at the same
    path (`ino`), or after a change beyond the first MiB (`regions_sha256`);
  * the token is spent after use;
* read-back negative controls: the backup header's CRC, a missing backup,
  backup entries, primary entries, the MBR type, the disk GUID differing
  between the copies, consistently rewritten but differing backup entries,
  a third partition, a wrong type, a wrong GUID against the receipt, and a
  moved partition.

The QEMU validation (sparse 8 GiB and 256 GB images, installs, refusals,
two AHCI boots each and a UEFI boot from the installed ESP) is recorded in
the lane record, not in this tree.
