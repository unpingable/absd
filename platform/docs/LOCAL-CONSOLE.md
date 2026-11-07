# Managed local console

The operator image built with kernel `ABSD_LOCAL_CONSOLE=1` serves local login
through the same shell, line discipline, process control and filesystem bindings
as SSH. It needs neither a NIC nor MWM. Init alone reads physical Console input;
children receive private pipes and never a physical keyboard capability. The
physical hardware_fixture display/keyboard path still requires an observed hardware run.

## Enrollment and rights

On the build host, create a fresh identity with:

```
python3 scripts/local-console-enroll.py --verifier local-login --token-file operator-token
```

Both files are created exclusively with mode 0600. Install **only** `local-login`
at `/ssh/local-login` through the image's existing filesystem-import/defaults
path. Keep `operator-token` outside the image under operator custody. It contains
a fresh random 128-bit token encoded as 32 lowercase hexadecimal characters.
The installed descriptor contains its SHA-256 verifier, not the token. This is
a random-token login, not a human-password storage scheme. No built-in identity
secret exists. Missing or malformed enrollment disables local shell access;
SSH public-key enrollment is separate and retains its existing policy. Rotate
local access by replacing the verifier in a halted image and retiring its old
token; live configuration changes and account management are not implemented.

The local identity is `operator`, with the same explicit rights as an SSH
operator session: `/home/operator` and its own `/tmp/session-N` writable;
`/bin`, `/etc`, `/share` and `/var/log` readable. `/ssh`, including the verifier
and SSH key material, is excluded. Its existing session-control channel admits
`ps`, `shutdown` and `reboot`; no machine capability is handed to a shell.

## Operating the console

Boot first prints the existing startup evidence. Init enables the login view
only after the worker's complete ready marker and a subsequent drain of FSD
startup records. Input before the prompt is discarded; Ctrl-] k still opens
read-only kernel maintenance while startup is held. Local readiness, including
an unenrolled view, does not establish an SSH listener or host network readiness.
After handoff, ordinary service output remains in `logs`; the raw serial worker
capture contains only the original startup prefix and has no complete-stream
END record. It is not a full service transcript. A boot without the local
console retains complete serial framing.

At `operator token:`, type the enrolled token and Enter. It is never echoed.
Failed authentication delays all local login views together by 2, 4, 8, 16,
then 30 seconds. Input during the delay is discarded. Resource/storage refusal
uses the same bounded delay per view and requires another explicit login.
There is no automatic shell respawn.

Press and release Ctrl-], then the indicated ordinary key:

| Key | Action |
| --- | --- |
| `1`, `2` | Select either retained text session; each requires its own login |
| `l` | End the selected session and clear its transcript and input |
| `k` | Select read-only kernel maintenance; repeat for a new snapshot |
| `r` | Return to the selected login/session and replay its retained transcript |

Only the selected view receives input. A partial token is erased when switching.
Each live session retains 16 KiB of display bytes; loss is marked. A busy or
hidden session is drained fairly so its output cannot block keyboard selection.
The local terminal uses `TERM=dumb`. Its initial dimensions are unknown
(0 by 0); `terminal-size` reports that observation. COLUMNS and LINES are
published only when actual dimensions are known. Local output uses newlines
and transcript replay rather than framebuffer ANSI cursor positioning. Shell
children inherit terminal observations through the existing metadata channel.
Terminal resize, raw mode, process groups and job control are not implemented.

Backspace/DEL erases a character, Ctrl-U erases the input line, Enter submits
it, and Ctrl-C clears the input line and interrupts the shell's current
foreground command over the existing control channel. The shell remains alive.
Ctrl-D after text submits it without a newline; Ctrl-D on an empty line closes
stdin permanently for that session. Logging out, EOF followed by shell exit,
or a shell fault closes private pipes, ends the session through the existing
bounded END protocol and releases its filesystem binding. After one second a
fresh token may start a fresh shell. No credentials, input or old transcript
are replayed into the replacement. Foreground jobs are session-bound;
deliberately detached jobs are not supported. The pre-existing forced-END
fallback can leave adopted processes, but releases their filesystem authority;
init reaps terminal orphans. This is not a process-tree termination guarantee.

## Recovery independent of services

Ctrl-] k is handled by init before keystrokes enter the worker pipe. It requires
neither FSD nor the logger, network stack, SSH listener, compositor or shell.
Physical Console possession explicitly grants only this kernel diagnostic read
view; it grants no shell or machine mutation. It prints bounded, sanitized
kernel log records with gap/truncation markers. Ctrl-] r resumes a working
worker's selected view. Maintenance keystrokes never reach a retained shell.
Service stdout/stderr use their captured logging streams rather than writing
asynchronous messages over the local command being entered.

SSH-specific startup failures (configuration, keys, entropy or networking)
enter local-only operation when the file server and enrollment remain usable.
A disabled NIC also leaves a running local session usable; it does not clear
driver quarantine. An authenticated operator can request an ordinary reboot.

Worker or file-server failure stops the essential services using init's
bounded cleanup. After readiness, the existing durable recovery budget permits
a visible reset. Before readiness or after budget exhaustion, a local-enabled
image holds read-only maintenance. This view grants no unauthenticated reboot
command; returning from that held state requires an external operator reboot.
No reset is described as an in-place service repair. Input relay overflow
discards the pending line and injects Ctrl-C to stop a partial command.

## Integration and replacement boundary

This changes startup composition, not live replacement. Role 19 is a dedicated
write-only worker-to-init terminal pipe and is never inherited by shell
children. Init retains the physical input authority. Producer/consumer golden
bytes are `user/tests/vectors/local-terminal-startup.hex` in the kernel and
`broker/vectors/local-terminal-startup.hex` here. Older runtimes reject the new
role rather than accepting an unnamed handle. Images must pin the matching
kernel/platform pair; no live transfer or downgrade compatibility is claimed.

Host tests cover routing, editing, EOF, interruption dispatch, authentication,
exhaustion/backoff, logout, shell death and bounded history. Actual foreground
interrupt/cleanup and no-NIC/dead-FSD observations must be checked on the
composed operator image. Serial-QEMU success does not establish hardware_fixture usability.

The served profile reserves six FSD session channels for the two local shells
(three channels each). Four SSH shells use twelve separate channels; remote
logins cannot consume the local reservation. Each shell receives a primary
channel and two spares for redirected concurrent children. Admission refuses
a shell unless its complete group is available. Logout returns the group only
after FSD acknowledges release. This reservation protects channels, not
unbounded process or pipe use by an explicitly spawning command.

The kernel profile provides 32 process slots, 128 handles per process,
128 pipes and 32 cells. A single spawn still transfers at most 64 handles.
Four services, six shells and three foreground children per shell occupy
28 process slots. Larger workloads receive ordinary resource refusals.
`ps` obtains the actual table bound from the kernel; on older kernels without
the capacity query it reports an unavailable census. Older `ps` binaries that
assume sixteen slots can miss processes in the upper half of this profile.
`sysinfo` prints both current occupancy and the kernel's reported limits.

## Distributable preview images

A preview disk must not contain `/ssh/local-login`. Build it with
`operator_image.py build --no-local-login` or pass `--no-local-login` to
`media.py operator-image`; keep the other required build arguments. This
option creates neither a token nor a verifier and cannot be combined with
`--local-token-file` or `--local-login-verifier`. Ordinary private operator
image builds retain their existing local enrollment default.

The preview producer still clears its temporary SSH authorized keys before
packaging. `absd-try` refuses a downloaded disk containing any local-login
file, even an empty one. The recipient enrolls their own SSH public key
through the existing enroll image; missing local enrollment disables local
login without changing SSH enrollment or boot.
