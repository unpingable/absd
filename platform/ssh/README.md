The login art in `motd.txt` was rendered once with FIGlet 2.2.5:

```sh
figlet -f standard ABSD
```

Trailing horizontal whitespace and the final empty line were removed. The
standard font file used was `/usr/share/figlet/standard.flf`, SHA256
`5bb2c59267559c141cf440884cef9b24ef2ddb7466f1bb2a8cf074b67d727bfe`.
The rendered text is committed and included in sshd at compile time. Neither
building an image nor starting a session needs FIGlet or its font file.

Only a successful shell request with a PTY on ABSD receives the banner. The
release line uses `absd_release::RELEASE_ID`: startup's existing
`require_server(0, true)` checks that identity against the file server's selected
release before sshd listens. The Linux reference backend has no installed ABSD
release and supplies no banner. Exec requests, including those with a PTY or
shell syntax, and shells without a PTY retain their existing output.

The pending banner is connection-local output, sent before echo or child
output and retained across short channel writes. It grants no authority and
changes no wire protocol, filesystem format or exported state schema. As with
the rest of the current SSH connection state, native Rust layout is not a
replacement protocol. A future admitted replacement must fence sessions and
either drain this queue or explicitly discard it when ending the old session;
it cannot infer authority to resume a fenced session from these bytes.

## Service diagnostic priorities

Known routine authentication, PTY/shell/exec acceptance, successful child
exit/reclamation and quiescent capacity observations use sshd's own stdout.
Init captures that stream with info priority 6; failures and unclassified
diagnostics keep stderr/warning priority 4. These streams are separate from
the session child's SSH stdout/stderr. A normal connection close is selected
from the actual protocol/EOF/shutdown event, not by matching log text.
The existing close path carries a diagnostic-only typed EOF/failure cause;
an I/O failure observed even after EOF keeps warning priority. If the normal
end was already reported, the first later I/O failure emits one warning;
repeated failure notifications do not repeat it. Close/drain
behavior, resource ownership and transport policy stay unchanged.
Nonzero/abnormal child outcomes and failed waits retain warning priority;
failed waits do not claim confirmed exit. A nonzero command status does not
by itself diagnose an sshd service failure. The retained J1 journal keeps
trusted source/PID/stream metadata; the legacy text projection accepts both
streams. No service receives new log-write authority or a logging protocol.

The capture helper ends its owned process group with TERM, then a bounded
KILL/reap fallback while the direct child still reserves that group identity.
It verifies group disappearance before retiring test keys. Unknown cleanup
retains the keys and reports their path; it does not claim retirement.
`python3 scripts/test_ssh_priority_cleanup.py` exercises TERM-ignoring and
already-exited real local children and cleanup after assertion and wait-timeout failures.

The focused host regression `scripts/test-ssh-priority.py --sshd BIN --work
FRESH_DIR` uses the existing SSH matrix client against the real Linux sshd,
checks separate service streams and guest command streams, and closes its
owned server and temporary keys. It requires no ABSD VM or remote host.
