# First-boot key enrollment

The developer preview ships its operator disk with an empty
`/ssh/authorized_keys`, so every copy belongs to nobody until its user adds a
key. An unenrolled disk does not serve. sshd refuses an empty key file
("no keys", `ssh/src/keys.rs`) before it listens, and `absd-try boot` refuses
such a disk before booting it. There is no shipped key and no fallback.

**Trust boundary.** Enrollment takes the user's public key over the
virtual machine's serial line. That line is trusted only inside the user's
own local QEMU, or a bootstrap environment that only the user controls.
It is not a remote or unattended enrollment service. Anyone who can write to
that serial line during an enrollment boot chooses the machine's operator
key.

## The enrollment image

The configuration decision recorded internally on 2026-10-16 makes the enrollment image
a separate image, chosen when it is built. No boot option enables
enrollment, and no ABI provides it.

- The kernel is built with `make ENROLL_STREAM=1 durable-iso DURABLE_STEP=1
  EXTERNAL_USER_ELF=absd-enroll.elf`. Its init runs one durable worker
  generation with the absd-stream-v1 serial input (kernel
  `docs/USERSPACE.md`). The image refuses to start if it also carries
  embedded input, a broker, a reader or a file server, or if it was granted
  a NIC.
- The worker is `absd-enroll.elf` (`ssh/src/enroll_main.rs`, built by
  `scripts/build-ssh.sh`). It reads the whole stream and judges it before it
  mounts anything:
  - The stream must hold exactly one importer record (`ABSDFIX1`) for
    `/ssh/authorized_keys`, at most 16 KiB, matching its SHA-256.
  - The bytes must be printable ASCII, tab and line ends only, with CR
    allowed only before LF.
  - Every key line must pass sshd's own `parse_authorized`, with at least
    one key and no key twice.

  Anything else is refused by name: `ENROLL REFUSED reason=malformed`,
  `duplicate`, `empty`, `extra-file`, `path`, `digest`, `truncated`,
  `too-large` and so on. The worker then exits 95 and the disk is not
  touched.
- An accepted key is written in one commit. The worker mounts the filesystem
  already on the disk, and never formats: a blank device is refused. It
  requires the writable placeholder the blank disk carries, replaces its
  bytes and syncs once. The filesystem commits nothing before that sync,
  so the commit protocol leaves the old file (empty on a first enrollment, the
  previous key set on a re-enrollment) or the new one. The
  enrollment matrix shows this only for an abrupt QEMU stop (model M1,
  docs/POWER-LOSS.md), not under the device law. The worker reads the file
  back and prints
  `ENROLL OK keys=<n> sha256=<hex>`.
- The helper (`scripts/absd_try.py enroll`) then reads the whole disk with
  the host reader. It requires exactly one new commit, the key file equal to
  what it sent, and every other object identical.

The helper validates the key with the same rules before sending it
(`key_lines`). The case files in `ssh/enroll-cases/` hold the helper and the
worker to the same verdicts: each file's name carries its expected verdict,
and both test suites read the directory.

An enrollment that does not finish is an explicit refusal, never SSH with
an empty key set. When the stream is refused or the enrollment boot stops
part-way, there are three outcomes (a storage or read-back error the worker
reports is a refusal of its own, with the disk as the error left it):

- The stream was refused, and the disk is unchanged.
- A stop left the old file. On a first enrollment that is the empty
  placeholder: the next boot is refused for want of a key, and the user
  enrolls again. On a re-enrollment, the previous keys still work.
- The key was committed, but the stop came before the helper saw
  `ENROLL OK`, so the acknowledgement was lost. The helper reports a failed
  enrollment while the disk holds the new key. Enrolling again replaces it
  with the same or another key in one more commit.

`scripts/enroll-matrix.py` boots the enrollment image under QEMU through
every case.
