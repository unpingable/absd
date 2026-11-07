# Host C/C++0 cross-development SDK

This is the short route from a staged SDK to a program running on ABSD.
The current SDK is a **local engineering candidate**. Full archive/header
licence qualification is pending an owner decision; no public SDK download or
publication is approved. Ask the operator for the staged SDK, compatible image,
checksums and login key. Do not treat a private build path as a download URL.

The SDK cross-compiles on Ubuntu 24.04 x86-64. It does not install a compiler
on ABSD. Its exact kernel/platform compatibility pair, actual runtime build
source, packaging tool identity and file inventory are in
`metadata/manifest.json`. Compatibility is a tested pair, not an ABI freeze.
Keep that pair's image, checksum and MANIFEST together. Packaging requires a
clean Git build-source checkout; exported source snapshots are refused.

## Install and verify on the development host

Install the host tools; building the SDK from source is not needed:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends python3 clang-18 lld-17 llvm-18 \
  libclang-rt-18-dev binutils openssh-client ca-certificates
sha256sum -c absd-sdk-VERSION.tar.gz.sha256
sha256sum -c operator-image.tar.gz.sha256
tar -xpzf absd-sdk-VERSION.tar.gz
```

The `-p` option preserves canonical file modes even under a restrictive umask.
The checker requires those exact recorded modes. Substitute the supplied
version and image archive names. Choose an extraction
path without whitespace: the established compiler drivers also require input
and output paths without whitespace. The directory may otherwise be moved.
Set `SDK` to the extracted directory's absolute path, then run:

```sh
"$SDK/bin/absd-sdk-check"
```

The checker verifies delivered files and actual compiler/linker/inspection
prerequisites, including clang's resource headers and builtins archive. It
reports licence qualification as pending. `--inventory-only` skips the host
probes; it is not a compilation test. The archive checksum binds the manifest
and its detached checksum; the embedded inventory binds every other file.
These are byte-consistency checks, not a signature or proof of origin.
No Rust, Cargo, CMake, Ninja or private checkout is needed to use the SDK.

## Build, upload, execute, change and repeat

This example counts input arguments and their character lengths. Choose your
own program once this works; a file argument is preferable to standard input.

```c
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t bytes = 0;
    for (int i = 1; i < argc; ++i) bytes += strlen(argv[i]);
    printf("words=%d bytes=%zu\n", argc - 1, bytes);
    return 0;
}
```

Save it as `words.c` on the development host:

```sh
"$SDK/bin/absd-cc" -O2 -o words words.c
"$SDK/bin/absd-check-elf" words --map words.map
```

Keep the generated `.map` and `.toolchain`: the map checker opens the SDK
archives named in that new link map, so compile again after relocating the
SDK. Output is a static x86-64 ELF in ABSD's image window, not a Linux binary.

For an already running ABSD machine, obtain its SSH destination/port, login
key, and host key from the operator. The next commands run on the development
host; `PORT` and `HOST` identify that machine. Keep the supplied known-hosts
file separate from unrelated machines.

```sh
ssh -i ./operator-key -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o ForwardAgent=no -o UserKnownHostsFile=./absd-known-hosts \
  -o StrictHostKeyChecking=yes -p "$PORT" operator@"$HOST" \
  'cat > /home/operator/words' < words
ssh -i ./operator-key -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o ForwardAgent=no -o UserKnownHostsFile=./absd-known-hosts \
  -o StrictHostKeyChecking=yes -p "$PORT" operator@"$HOST" \
  '/home/operator/words apple pear'
```

Expected output: `words=2 bytes=9`. Change the printed label or counting
rule, rebuild, check, upload again and rerun; verify the changed output.
The `cat` transport above works without a terminal. Images that ship
`absd-sftp(8)` also support ordinary OpenSSH `sftp` and default `scp`; consult
that image's manual for bounds and unsupported metadata-preserving options.
The exact SDK/image compatibility pair still governs this workflow.
Direct execution of an
uploaded absolute path is fixed in the compatible development pair (#119).
There is no need for a shell-syntax workaround on this pair.

A test operator image can be booted locally under QEMU using its supplied
launcher or the documented image instructions. Its SSH forward must bind
loopback; `127.0.0.1` always means the computer running QEMU. On a headless
remote host, use its established authenticated access path. Neither a path
on build_host nor build_host's loopback address is a client endpoint.

## Optional C++0

If `bin/absd-c++` is included, it uses the packaged C kit and LLVM 18.1.8
libc++/libc++abi headers and static archives. Build and inspect like C:

```sh
"$SDK/bin/absd-c++" -std=c++17 -O2 -o program program.cpp
"$SDK/bin/absd-check-elf" program --map program.map
```

Classes, virtual dispatch, templates, containers, strings and constructors/
destructors are supported within the existing C++0 profile. Use `<cstdio>`
for output. There are no exceptions, application RTTI, true C++ threads,
iostreams/localization or `std::filesystem`; unsupported flags such as
`-fexceptions`, `-frtti` and `-pthread` are refused. The separate LLVM-tool
runtime profile is not part of C++0. Do not substitute host libstdc++ or an
unrelated C kit. A kit/runtime libc mismatch is refused. C++ acceptance is
reported separately from the C baseline.

## Limits and troubleshooting

- Use arguments or named files for this staged-SDK workflow; the #121 examples
  do not qualify C standard input. At the descriptor layer, reads of an open
  descriptor 0 delegate to the runtime's startup input stream: an absent input
  handle yields EOF, while a closed descriptor or invalid handle can yield
  `EBADF`. The earlier Develop report's stdin `EBADF` finding is not a blanket
  adapter refusal or qualification of other startup-stream arrangements.
- This is the bounded static, single-task C/C++ runtime. Details and refusal
  semantics are in `docs/C-INTERFACE.md` and `cxx/README.md` in the matching
  platform source; neither source checkout is required for this workflow.
- A missing clang builtins archive needs `libclang-rt-18-dev`; a missing
  `llvm-nm-18` needs `llvm-18`, and `readelf` needs `binutils`.
- A wrong compiler or linker major version is refused. Keep the tools listed
  above and inspect the output's `.toolchain` record.
- For an inventory mode mismatch, extract a fresh copy with
  `tar -xpzf absd-sdk-VERSION.tar.gz`; `-p` preserves the recorded modes under
  a restrictive umask. For another inventory mismatch, verify the original
  archive checksum and extract a fresh copy with the same command. Do not
  edit recorded modes or digests to make a check pass.
- SSH status 127, refusal text or a nonzero program status is a failure to
  investigate. Capture the actual command/output and image/SDK identities;
  an older image's successful test does not qualify a new pair.

## Maintainer entrypoint

`scripts/package-sdk.py --help` documents the local packaging command.
Provide a clean actual Git build checkout, fresh default C kit and its pinned
Picolibc install, optional C++0 output, explicit version and compatibility
commits, and a new output directory. Experimental/profile and unknown C
receipt fields are refused; optional C++ is restricted to the established
C++0 profile. The copied ELF checker must equal the actual build source's
checker, so a source revision with different loader rules needs a matching
packager checkout. The packager verifies source-bound
libraries, drivers and headers, creates a deterministic archive and full
inventory, and copies supplied notice evidence without granting clearance.
Original build receipts remain in the owning build evidence; installed
sanitized receipts preserve source/tool/archive identities and record the
original receipt hashes. Full downloadable-content provenance and independent
archive-only execution are required before any distribution decision. Full
archive/header licence qualification is held for an owner decision; this lane
does not broaden licence labels or gate policy.

### Bounded readable waits

`<absd/syscall.h>` exposes `absd_wait_readable(handles, count, ticks)`,
`ABSD_SYS_WAIT_READABLE` (0x7fa8), `ABSD_WAIT_READABLE_MAX` (11), and
`ABSD_WAIT_READABLE_POLL` (UINT64_MAX). The thin wrapper returns the raw signed
result and always issues the call, including empty sets. This is an additive
ABI 1 interface: an older kernel returns -38. See `wait_readable(2)` for
readiness, timeout, EOF and authority semantics. The installed header is included
in the existing SDK inventory and hash verification.
