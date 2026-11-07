# Operator toolbox inventory

Canonical task inventory for coordination record #53; observed 2026-11-05. This is
an ordinary SSH toolbox inventory, not NetBSD parity or qualification.

Source inspection uses platform `0c4750bcbdf9740a8075b984fa9525978aeaa01d`
and kernel `94a014e6` as requested by the integration steward. The reference
available image is older: its MANIFEST names platform
`484a4419cbe885a6ee16784ec5809f218282eba9` and kernel
`4e0aa40eb9b7bd8b634bf37e0ecd0df380859f74`. Later source features are not
silently attributed to that image. New #53 work starts at platform
`2eb2240e34fffb566470b342edbb1d5be8f98228` / kernel
`82e470de1850b55fef0632cad248e5a18d8433ae`.

The #53 candidate is platform `64275922` on the same kernel. Its separate
image now installs `tr` and `dirname`; both passed the SSH checks below.
That candidate result does not add commands to the older #148 reference
image. E2 identifies this actual candidate SSH evidence; E1 identifies the
existing #149 trial of the reference image.

The first tranche is integrated at `dc3c981a`. The second #53 image is
platform `086c4d81` on kernel `82e470de`; it adds `tee` and `sleep`. E3
identifies its separate actual SSH evidence. It installs 49 commands and
66 rendered manual pages plus the index. These observations do not change
the older #148 reference image or claim the pending composed integration.

The current adaptation carries the reviewed tee/sleep packaging onto
integrated stderr/null base `bac8a3d6`, with the steward's throughput
commit to follow before final composition. Its own runtime is pending;
E3 continues to identify the original `086c4d81` image above. Both original
#53 provider occurrences used first-contact host-key trust followed by strict
pinning, without provider-console verification; their VMs and private keys
are retired. The retained engineering observations carry that limitation.

Evidence retained by the integration steward and the producing lanes:

- `toolbox-53-20261105/image-MANIFEST` and `image-contents.json`: read-only
  image declaration and independent filesystem read; all 51 actual release
  binaries match their declared hashes. Acquired over established staging_host SSH.
- `operability-148-20261104/operator-trial149-evidence/`: actual interactive,
  reconnect and restart SSH transcripts and final black-box findings.
- `operability-148-20261104/offline-diagnostics01.json`: actual device-down
  console observations; these support local diagnostics, not an SSH claim.
- `toolbox-53-20261105/runtime01/`: candidate MANIFEST, consumed-buffer
  hashes, `SSH-RESULTS.json` (18 golden utility cases, both manuals, binary
  transfer and protocol refusals), and `interactive.typescript`. The
  interactive run also exposed the new manuals' single-quote example
  defect; corrected recipes were shown working on the same baseline shell.
- `toolbox-53-20261105/runtime02/`: consumed-buffer hashes, candidate
  MANIFEST and `SSH-RESULTS.json` (19 declared utility outcomes, both exact
  manuals, existing-file signal refusal, closed-stdout continuation,
  delivered timer observation, all new manual examples and fixture cleanup).
  `INTERRUPT-SLEEP.json` and its transcript confirm the sleeping child
  started and ended, status 130, and the session remained usable. E3 has
  28 checks; it is ordinary development evidence, not qualification.
- Platform `scripts/operator_image.py`, `src/bin/`, `man/`,
  `userland/PORTS.tsv` and `userland/DEMAND-SUMMARY.tsv`: image catalog,
  implementation, interfaces, exact C binary pins and existing portability probe.

In the table, **usable** means the named bounded task was observed in the
SSH trial (E1 or E2), or implementation and image exposure were checked but runtime
is explicitly **unverified** (S). A command name alone is never an execution
result. **Implemented, not exposed** means a real source implementation or
pinned upstream is present but the operator image does not install it.
**Broken** describes a concrete observed failure or incomplete behavior.
**Absent** means no operator entry point exists in this image/catalog.
Checks are repeatable recipes or acceptance sketches; unrun recipes remain
unverified. Writable test files belong below the operator's own home directory.

| Operator task | Current operation / source | Status and observation | Observable check and refusal/visibility limit | Disposition / owner |
| --- | --- | --- | --- | --- |
| Identify release and machine | `release`, `uname`, `sysinfo` | Usable, E1 | `release; uname; sysinfo`; release is served identity, not a hardware qualification claim | Existing; #148 |
| Inspect uptime and available memory | `uptime`, `sysinfo` | Usable, E1 | `uptime; sysinfo`; frame counts are live; CPU load, pressure, per-process RSS and CPU% remain unknown | Existing; #53, kernel measurement work deferred |
| See current processes | shell `ps`, native `ps -A` | Usable, E1 | `ps; ps -A`; per-row snapshots, PID scoped to boot; no argv/RSS/CPU% | Existing; #148/#133 |
| Inspect a service and recent failure | `status`, `health`, `dmesg`, `logs --volatile -u sshd` | Usable within bounded current-boot view, E1 | `health; logs --volatile -u sshd`; history is bounded and loss must remain visible | Existing; #148/#145/#147 |
| Read retained live service history | `logs -u sshd`, `logs --health` | Broken, E1: empty success while volatile records show activity; suppressed grows | Compare retained and volatile output after an SSH login; current failure does not imply all previous-boot history is absent | Fix already owned by #148/#147 |
| Inspect file/socket holders | no `lsof`/`fuser` equivalent | Absent | Catalog has no per-object holder query; process handle counts do not identify resources | Native candidate only after observer/API scope exists; deferred |
| List interfaces and link state | `interfaces` | Usable, E1 | `interfaces`; negotiated speed, jack mapping and duplex explicitly unknown | Existing; #148; hardware #146 deferred |
| Inspect configured address/route/listener | `net-status` | Usable retained observation, E1 | `net-status`; inspect age/stale notice; retained data is not current reachability | Existing; network owner |
| Probe an arbitrary TCP peer or DNS answer | standalone network probe programs, no installed `nc`/`dig` | Implemented, not exposed (test/demo programs), S | `ls /bin`; no ordinary composed-system probe command or operator grant | Native candidate; network owner, deferred here |
| Fetch an HTTP document | optional `https-document`, no general `curl` | Implemented, not exposed in this actual image, S | Inspect image catalog and `ABSD_HTTPS_DOCUMENT`; optional named workload is not an arbitrary HTTP client | Existing optional facility; broader client deferred |
| Inspect filesystem capacity | `df`, `sysinfo` | Usable, E1 | `df`; reports served filesystem accounting, not host disk space | Existing; do not rebuild |
| Inspect file size and metadata | `stat`, `ls` | Usable exposure, S; individual metadata cases unverified | `stat notes.sh; stat missing`; refuse missing paths; no Unix UID/GID/mode or mount inventory claim | Existing; #53 |
| Find large directories | no `du`; sbase needs unresolved `fdopendir`, `fstatat`, `openat` | Absent; upstream implementation cannot link with current adapter | Existing demand row is deterministic negative; no guessed allocated-block accounting | Compatible port deferred pending adapter consumer |
| Create/copy/move/remove files and directories | `mkdir`, `cp`, `mv`, `rm`, shell redirects | Usable, E1 for trial file work | Within own test dir, create then `cp`, `mv`, `cmp`, `rm`; missing paths must fail; no permission emulation | Existing |
| Search names and text | `find`, `grep`, `rg` | Usable, E1 | `find . -name "*.txt"; grep -n text notes.txt`; quoted patterns and spaced names observed | Existing portable upstream |
| Replace, sort and deduplicate text | `sed`, `sort`, `uniq`, `cut`, `head`, `tail`, `wc` | Usable for observed pipeline, E1; full option surface unverified | `cat notes.txt \| sort \| uniq`; check actual output and status; consult per-command restrictions | Existing portable upstream/native |
| Translate/delete/squeeze characters | pinned unmodified sbase `tr.c`, candidate `/bin/tr` | Usable in #53 candidate, E2: 10 SSH cases plus interactive pipelines | Translation, deletion, squeeze, complement, UTF-8/classes, empty input and invalid arguments match host golden results; inherited streams only | Delivered compatible port in #53; absent in older reference image |
| Extract a parent directory in a script | pinned unmodified sbase `dirname.c`, candidate `/bin/dirname` | Usable in #53 candidate, E2: 8 SSH cases and interactive spaced path | Absolute/relative/root/trailing slash/spaced/empty strings and missing/extra operands match host golden results; no file opened | Delivered compatible port in #53; absent in older reference image |
| Save a pipeline while displaying it | pinned unmodified sbase `tee.c`, candidate `/bin/tee` | Usable in second #53 candidate, E3: 11 SSH cases plus two output/refusal checks | Append/truncate, binary EOF and partial-open errors match declared outcomes; `-i` refuses before opening an existing file; a closed stdout is diagnosed while the other 65536-byte file completes | Delivered compatible port in #53; absent in older reference image |
| Delay a script | pinned unmodified sbase `sleep.c`, existing `c/libabs/clock.c` delay, candidate `/bin/sleep` | Usable in second #53 candidate, E3: 8 SSH cases, same-boot timer observation and session interruption | Whole unsigned seconds only; zero and misuse outcomes match; `sleep 1` advanced 1154 delivered ticks in the observed session, not a physical clock-accuracy claim; Ctrl-C ended the child with status 130 and restored a usable prompt | Delivered compatible port in #53; absent in older reference image |
| Process tabular text with a language | no `awk` in image or pinned sbase 0.1 | Absent | No ordinary entry point; `cut`/`sed` cover some jobs, not an awk language implementation | Evaluate a portable upstream against the C-kit demand before importing; later #53 vertical |
| Inspect or set a command environment | `printenv` exists; sbase `env` needs unresolved `execve` | Inspection usable via existing tool; `env` command absent | `printenv`; full `env` must also invoke a child with an explicit environment, not just print variables | Existing inspection first; command-prefix semantics #133, compatible `env` deferred pending process adapter |
| Edit full-screen | no installed `vi` or qualified portable terminal profile | Absent | `ed` is observed working, but does not establish full-screen editing; identify real terminal/termios needs before selecting a port | Later compatible editor; coordinate #133 terminal owner |
| Move files over SSH | ordinary non-PTY SSH exec streams | Usable, E2: 8192 binary bytes round-trip unchanged | Client upload `ssh host "cat > /home/operator/f" < local`; download `ssh host "cat /home/operator/f" > local`; compare bytes/SHA256; preserve caller mounts | Existing, documented in afterboot(8) and operator matrix; #53 verified it |
| Transfer with SCP/SFTP | no SSH subsystem and no `/bin/scp` receiver | Absent, E2: legacy receiver exit 127 and SFTP request exit 255 | Unsupported protocols refuse; original transferred binary remains unchanged; no native SSH/SFTP client installed either | Protocol/FSD-bound server work belongs platform `ssh/`, existing #148 owner Codex 01a1a788; #53 owns inventory and client instructions |
| Apply commands to found paths | `find -exec` explicitly unsupported; no `xargs` | Absent; upstream xargs needs unresolved `fork`, `execve`, `waitpid` | Missing program/unsupported option must fail, not silently skip files | Deferred; no new shell/process API in #53 |
| Edit a small file | `ed` | Usable, E1; shell-manual recipe broken | Explicit editor prompt, append, `.`, write, quit, reopen; documented recipe omitted append terminator | Existing; docs fix #76/#148 |
| Read a long file comfortably | `head`, `tail`, `sed -n`; no `less`/`more` | Usable bounded slices; interactive pager absent | `sed -n "1,20p" notes.txt`; no full-screen terminal claim | Compatible pager candidate later; #133 terminal owner |
| Archive and restore | sbase `tar`, `cmp` | Usable, E1 | Create/list/extract own directory, then `cmp` original/restored; unsupported metadata modes documented | Existing; `gzip` absent/deferred |
| Run a small script with arguments | `sh`, `./script`, quoting/globs/pipelines | Usable, E1; shell/application paste routing broken | Script receives `first` and `two words`; paste `cat` and following input reproduces queued shell interpretation | Existing; paste repair #133/#148 |
| Read delivered command manuals | `man`, versioned rendered pages | Usable exposure, S; E1 exposes stale claims | `man ps; man ed`; docs disagree with image on global ps and sizing | Existing; #76/#148 corrections |
| Observe civil time | `date` | Usable exposure, S; clock correction not in this image | `date`; newer source #42 software clock/SNTP work is separate from accepted runtime | Existing; #42 owns pending fix |
| Commit and retain work across login/reboot | `sync -v`, persistent home, session-private `/tmp` | Usable, E1: same marker digest after reconnect and orderly restart | Write marker, `sync -v`, reconnect then coordinated restart; compare `sha256sum` | Existing; abrupt loss not assessed |
| Change network/SSH configuration with recovery | #148 config-recovery slice, not original image | Implemented, not exposed in this image, S | Needs candidate timeout/confirm/refusal SSH drill; source tests alone insufficient | Existing #134/#148 owner; no duplicate |
| Build/deploy from the target | no installed `make`, `git`, SSH/SFTP client, `rsync`, `jq` | Absent | `ls /bin` and manifest; cross-development support is not native tool availability | Later compatible ports; U5/#121 |

## First-hour priority and scope

1. Concrete observed logging, paste routing and misleading manual defects
   matter most; their active owners are #148/#147, #133 and #76. This lane
   supplies evidence and does not duplicate them.
2. Pinned sbase `tr` and `dirname` are now packaged and shown working over
   SSH, with source manuals and regression cases. The image/catalog and
   binary pins, rather than a new implementation, expose these operations.
3. Next in first-hour order: use the already working SSH file-transfer path;
   `tr`, `dirname`, `tee` and `sleep` are delivered in the two slices. Address `xargs`,
   `du`, `awk`, environment invocation and `vi` as their actual process,
   filesystem or terminal prerequisites permit. `dirname` was completed in
   this slice as the small existing counterpart to `basename`.
   The current probe covers 97 sbase utilities with 59 compiling, linking
   and passing the ELF gate. This is a portability observation, not a claim
   that those 59 utilities are shipped or behave correctly on ABSD.
4. SCP/SFTP needs SSH server and FSD session work in the existing #148
   component, while ordinary SSH byte-stream copying works today. No second
   sshd or shell lane is started here.

Each delivered fix requires pinned installed bytes, a manual, positive and
negative regression cases, actual SSH execution on its candidate image,
and non-Codex review commissioned through the integration steward. A host
build is not an SSH pass. Rollback is the previous image/catalog; this work
changes no persistent format or authority. Existing readers and service
generations are untouched. Practical byte-level build and task tests suffice
for these ordinary utilities; no nontrivial state-transfer claim is made.

## Third tranche source investigation, November 5

The third tranche packages pinned sbase `rmdir` and `paste`. `rmdir` removes
empty directories (including `-p` parents); `paste` combines file columns or
joins lines sequentially. Both use existing adapters, with manuals and host
cases. The bounded SSH observations are recorded below.
`true` and `false` already work in the shell language and need no new binaries.

Other suggested commands remain gaps for concrete reasons: `touch` lacks
working timestamp operations in the current C interface; `ln` needs absent
hard/symbolic links; `env` and `xargs` need process invocation adapters;
`which` needs the unresolved metadata/access adapters; `du` needs directory
metadata and truthful allocation accounting; `kill` reaches a refusing C
adapter. `clear` and an interactive pager need a deliberate terminal profile
and remain outside this small existing-source tranche.

The pinned sbase `expr` source was investigated and dropped: a host reference
build crashes when comparing a calculated result (`expr "(" 2 + 3 ")" = 5`).
The arithmetic result has no string pointer, but the comparison path expects
one. Any future `expr` packaging must fix or replace that source and test
calculated-value comparisons before exposing it. This is an upstream host
finding, not an observed ABSD result.

The third-tranche source `880ed0b4` has since passed 21 operator observations
over SSH: 18 declared utility cases, both exact manuals and directory effects.
The guest shut down normally and all 124 installed buffers read back unchanged.
The complete diagnostic remains failed because its last fixture cleanup used
`rm -rf`, which that native rm did not accept. The steward accepted the bounded
operator evidence for ordinary integration; the failed workflow verdict remains
in `toolbox-53-t3-01a1ac9f-20261105/runtime02/` evidence.

The native rm follow-up adds `-f` and clustered `-rf`/`-fr` support while
preserving every error other than a missing path and preserving mount refusals.
Its real-source host binary tests use the host filesystem and a fixture mount
inventory. Source `a5abe057`, over platform `40f09aee` with kernel `1a44e3c2`,
passed 27 focused SSH observations in `rm-force53-runtime02-01a1ac9f`.
Both flag orders removed populated directories, missing operands were quiet,
read-only and mount refusals still failed, later operands ran after an error,
and the installed manual matched exactly. The guest shut down normally, all
89 installed buffers read back unchanged, and no test fixture remained. This
is focused command evidence, not a full matrix or release qualification.
