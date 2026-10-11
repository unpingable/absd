#!/usr/bin/env python3
"""The file server matrix: storage for SSH sessions on ABSD.

One `net fsd` boot at a time (scripts/ssh_absd.py): init starts absd-fsd
with the only read-write block handle and sshd with its control channel and
client slots. Every client is the host's /usr/bin/ssh with strict host key
checking; sessions run the platform's commands and /bin/fsd-probe
(src/bin/fsd_probe.rs). After every boot the host reads the image back with
its own filesystem reader (scripts/absd_fs.py) where a claim is about what
reached the device.

Markers (each printed only when every check behind it held):

  SESSION WRITE OK               a session creates, appends, renames, and
                                 removes under /home/operator and its /tmp
  SESSION WRITE PERSISTENCE OK   across reconnect and reboot, and on the
                                 device as the host reads it
  SYSTEM WRITE REFUSED OK        /bin, /etc (read-only), /ssh and anything
                                 outside the mounts (absent), unchanged
  RAW BLOCK REFUSED OK           a session and its children hold no block
                                 handle: every handle number is refused
  SSH HOST KEY ISOLATED OK       sshd signs; no session or shell child can
                                 open /ssh/*, by any path; reconnect and
                                 reboot keep the key
  SHELL AUTHORITY NARROWING OK   a redirected command gets a pipe, not the
                                 file; `ro`/`nofs` children cannot write
  SSH MULTI SESSION OK           simultaneous sessions, each served; with
                                 all four connected each shell has a spare
  FS MULTI SESSION COHERENCE OK  independent cwd and /tmp; simultaneous
                                 reads; writes to different files;
                                 competing create-new and rename; a session
                                 disconnecting mid-write; one dying while
                                 another continues; listener survives;
                                 reconnect after churn
  SESSION FAILURE ISOLATION OK   a session that breaks its channel's
                                 framing, faults, or is killed affects no
                                 other session, and its slot serves again
"""

import argparse
import importlib.util
import pathlib
import re
import subprocess
import sys
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

PROMPT = b"absd$ "
SEED = ssh_absd.SEED_PATH


def lines(out):
    return out.replace(PROMPT, b"").decode(errors="replace").splitlines()


class FsdMatrix(sm.Matrix):
    def shell(self, script, timeout=600):
        """One non-PTY shell session running `script` (lines)."""
        return self.ssh(None, stdin=("\n".join(script) + "\n").encode(), timeout=timeout)

    def shell_async(self, script):
        p = subprocess.Popen(self.client.base(self.op), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.stdin.write(("\n".join(script) + "\n").encode())
        p.stdin.close()
        return p

    def finish(self, p, timeout=600):
        # stdin is already written and closed: read both streams to the end.
        p.stdin = None
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err

    def device(self):
        return self.t.tree()

    def run(self):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        first = t.start(fresh=True)
        self.client = sm.Client(self.work, t.port)
        self.check("file server generated the host key on first boot", first["generated"], str(first))
        host_key = first["public"]
        self.client.trust(host_key)
        serial = t.serial()
        self.check("sshd holds no block handle; its control channel sees /ssh, /bin, /etc read-only, /var/log read-write",
                   re.search(r"SSH STORAGE VIA FILE SERVER OK block=none control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,/var/state:ro,/var/state/facts:rw slots=10",
                             t.output())
                   is not None, t.output()[-600:])
        self.check("the file server is the one process with the block handle",
                   "FILE SERVER START pid=2 channels=11" in serial and "SPAWN OK pid=2 parent=1 program=file-server" in serial,
                   serial[-800:])
        system = {path: data for path, data in self.device().items()
                  if path.startswith(ssh_absd.SYSTEM_PREFIXES)}
        self.check("the release tree holds /bin on the device",
                   t.physical("/bin/ls") in system and "/absd/selected" in system, str(sorted(system))[:600])

        # -- SESSION WRITE ------------------------------------------------------
        rc, out, err = self.shell([
            "echo hello > /home/operator/hello",
            "echo more >> /home/operator/hello",
            "cat /home/operator/hello",
            "mkdir /home/operator/dir",
            "mv /home/operator/hello /home/operator/dir/hello",
            "ls /home/operator/dir",
            "echo scratch > /tmp/session-1/s",
            "cat /tmp/session-1/s",
            "echo gone > /home/operator/gone",
            "rm /home/operator/gone",
            "ls /home/operator",
            "/bin/fsd-probe write /home/operator/big 200000",
        ])
        shown = lines(out)
        self.check("shell writes, appends, renames, and removes in /home/operator and its /tmp",
                   rc == 0 and shown[:5] == ["hello", "more", "hello", "scratch", "dir/"]
                   and shown[5].startswith("write: 200000 bytes") and err == b"",
                   f"rc={rc} out={shown} err={err!r}")
        tree = self.device()
        pattern = bytes(i % 251 for i in range(200000))
        self.check("the host reads the session's files from the device",
                   tree.get("/home/operator/dir/hello") == b"hello\nmore\n"
                   and tree.get("/home/operator/big") == pattern and "/home/operator/gone" not in tree,
                   str(sorted(p for p in tree if p.startswith("/home"))))
        rc, out, err = self.ssh("/bin/fsd-probe write /home/operator/exec-written 5000")
        self.check("an exec command writes too", rc == 0 and out.startswith(b"write: 5000 bytes"), f"{rc} {out!r} {err!r}")
        self.mark("SESSION WRITE OK")

        # -- SYSTEM WRITE REFUSED -------------------------------------------------
        rc, out, err = self.shell([
            "echo x > /bin/evil",
            "echo x > /etc/motd",
            "echo x > /ssh/authorized_keys",
            "echo x > /var-new",
            "rm /bin/ls",
            "mv /bin/ls /home/operator/ls",
            "mkdir /bin/sub",
            "mkdir /opt",
            "rm -r /home/operator/../../bin",
            "/bin/fsd-probe try-write /tmp/session-1/../../bin/x",
            "/bin/fsd-probe try-write /home/operator/../../etc/passwd",
            "/bin/fsd-probe try-write /tmp/session-99/x",
            "/bin/fsd-probe try-write /ssh/host_ed25519_seed",
        ])
        text = err.decode(errors="replace")
        refusals = [
            "absd-sh: /bin/evil: cannot write: read-only here",
            "absd-sh: /etc/motd: cannot write: read-only here",
            "absd-sh: /ssh/authorized_keys: not found",
            "absd-sh: /var-new: not found",
            "rm: /bin/ls: ABSD filesystem is mounted read-only",
            "mv: /bin/ls -> /home/operator/ls: ABSD filesystem is mounted read-only",
            "mkdir: /bin/sub: ABSD filesystem is mounted read-only",
            "mkdir: /opt: ABSD path not found",
        ]
        missing = [r for r in refusals if r not in text]
        probes = [line for line in lines(out) if line.startswith("try-write:")]
        self.check("writes to /bin, /etc, /ssh, and outside the mounts are refused by name",
                   not missing and probes == [
                       "try-write: ReadOnlyFilesystem /tmp/session-1/../../bin/x",
                       "try-write: ReadOnlyFilesystem /home/operator/../../etc/passwd",
                       "try-write: NotFound /tmp/session-99/x",
                       "try-write: NotFound /ssh/host_ed25519_seed",
                   ], f"missing={missing} probes={probes} err={text[-800:]!r}")
        after = {path: data for path, data in self.device().items() if path.startswith(ssh_absd.SYSTEM_PREFIXES)}
        self.check("/bin, /etc, /ssh (and the release tree and selection) unchanged on the device", after == system,
                   str(set(after) ^ set(system)))
        self.mark("SYSTEM WRITE REFUSED OK")

        # -- RAW BLOCK REFUSED ----------------------------------------------------
        rc, out, err = self.ssh("/bin/fsd-probe block")
        self.check("an exec command holds no block handle", rc == 0 and out == b"block: REFUSED handles=64 block_handle=0\n",
                   f"{rc} {out!r} {err!r}")
        rc, out, err = self.shell(["/bin/fsd-probe block", "/bin/fsd-probe spawn /bin/fsd-probe block",
                                   "ro /bin/fsd-probe block"])
        blocks = [line for line in lines(out) if line.startswith("block:")]
        # A shell's child has no spawn right: the grandchild never starts,
        # and the refusal is the kernel's permission refusal, not another
        # failure to start.
        refused = [line for line in lines(out) if line.startswith("spawn: /bin/fsd-probe: ")]
        self.check("a shell and its children hold no block handle; a child cannot start a grandchild",
                   blocks == ["block: REFUSED handles=64 block_handle=0"] * 2
                   and refused == ["spawn: /bin/fsd-probe: permission denied"],
                   f"{blocks} {refused} {err!r}")
        self.mark("RAW BLOCK REFUSED OK")

        # -- SSH HOST KEY ISOLATED --------------------------------------------------
        seed = self.device()[SEED]
        leaked = []
        for command in [f"/bin/cat {SEED}", "/bin/cat /home/operator/../../ssh/host_ed25519_seed",
                        "/bin/ls /ssh", f"/bin/fsd-probe try-read {SEED}", "/bin/fsd-probe try-read /ssh",
                        "/bin/fsd-probe mounts"]:
            rc, out, err = self.ssh(command)
            listed = [l.strip() for l in out.splitlines()]
            if (seed in out or seed in err or b"host_ed25519_seed" in listed or b"try-read: OK" in out
                    or b"/ssh:" in out or rc == 0 and not command.endswith("mounts")):
                leaked.append(command)
        rc, out, err = self.shell([f"cat {SEED}", f"/bin/fsd-probe spawn /bin/cat {SEED}",
                                   f"ro /bin/fsd-probe try-read {SEED}", "cd /ssh", "ls /"])
        shell_leak = seed in out or seed in err
        self.check("no session, shell, or shell child can open /ssh/* by any path",
                   not leaked and not shell_leak and "ssh/" not in lines(out)
                   and "absd-sh: cd: /ssh: not found" in err.decode(errors="replace"),
                   f"leaked={leaked} out={lines(out)} err={err[-400:]!r}")
        rc, out, err = self.ssh("echo signed", extra=("-v",))
        self.check("sshd signs with the key it read at start (strict known_hosts)",
                   rc == 0 and out == b"signed\n" and b"Server host key: ssh-ed25519" in err, err[-300:].decode(errors="replace"))

        # -- persistence across reboot, with the key ---------------------------------
        second = t.restart()
        self.check("reboot: host key loaded, the same", not second["generated"] and second["public"] == host_key, str(second))
        rc, out, err = self.shell(["cat /home/operator/dir/hello", "ls /tmp", "/bin/fsd-probe read /home/operator/big"])
        shown = lines(out)
        self.check("reboot: the session's files are there; this boot's session has a fresh /tmp",
                   rc == 0 and shown[:3] == ["hello", "more", "session-1/"] and shown[3].startswith("read: 200000 bytes"),
                   f"{shown} {err!r}")
        rc, out, err = self.ssh("/bin/cat /home/operator/dir/hello")
        self.check("reconnect: the same files", rc == 0 and out == b"hello\nmore\n", f"{rc} {out!r}")
        self.mark("SESSION WRITE PERSISTENCE OK")
        self.mark("SSH HOST KEY ISOLATED OK")

        # -- SHELL AUTHORITY NARROWING (over SSH) ----------------------------------------
        rc, out, err = self.shell([
            "ro /bin/fsd-probe try-write /home/operator/other > /home/operator/redir",
            "ro /bin/fsd-probe try-write /home/operator/redir >> /home/operator/redir",
            "nofs /bin/fsd-probe try-read /etc/motd >> /home/operator/redir",
            "nofs /bin/fsd-probe block >> /home/operator/redir",
            "ro /bin/fsd-probe mounts >> /home/operator/redir",
            "/bin/fsd-probe mounts >> /home/operator/redir",
            "cat /home/operator/redir",
        ])
        shown = lines(out)
        tmp = re.search(r"/tmp/session-\d+", out.decode(errors="replace"))
        tmp = tmp.group(0) if tmp else "?"
        expected = [
            "try-write: ReadOnlyFilesystem /home/operator/other",
            "try-write: ReadOnlyFilesystem /home/operator/redir",
            "try-read: NotFound /etc/motd",
            "block: REFUSED handles=64 block_handle=0",
            f"mounts: /home/operator:ro,{tmp}:ro,/bin:ro,/etc:ro,/share:ro,/var/log:ro",
            f"mounts: /home/operator:rw,{tmp}:rw,/bin:ro,/etc:ro,/share:ro,/var/log:ro",
        ]
        tree = self.device()
        self.check("a redirected command gets the pipe, not the file: ro/nofs children write nothing",
                   shown == expected and "/home/operator/other" not in tree
                   and tree.get("/home/operator/redir", b"").decode().splitlines() == expected,
                   f"{shown} err={err!r}")
        self.mark("SHELL AUTHORITY NARROWING OK")

        # -- SSH MULTI SESSION + COHERENCE ---------------------------------------------------
        a = self.shell_async(["cd /etc", "pwd", "ls /tmp", "/bin/fsd-probe read /bin/absd-sh",
                              "/bin/fsd-probe hold /home/operator/a-file 4000", "pwd"])
        b = self.shell_async(["cd /home/operator", "pwd", "ls /tmp", "/bin/fsd-probe read /bin/absd-sh",
                              "/bin/fsd-probe hold /home/operator/b-file 4000", "pwd"])
        (ra, oa, ea), (rb, ob, eb) = self.finish(a), self.finish(b)
        la, lb = lines(oa), lines(ob)
        size = len((self.root_path() / "commands" / "absd-sh").read_bytes())
        self.check("two simultaneous shells: independent cwd and /tmp, simultaneous reads",
                   ra == 0 and rb == 0 and la[0] == "/etc" and lb[0] == "/home/operator" and la[-1] == "/etc"
                   and lb[-1] == "/home/operator" and len(la[1:2]) == 1 and len(lb[1:2]) == 1 and la[1] != lb[1]
                   and la[2].startswith(f"read: {size} bytes") and lb[2].startswith(f"read: {size} bytes"),
                   f"a={la} {ea!r} b={lb} {eb!r}")
        tree = self.device()
        ok = True
        for name, out in [("a", la), ("b", lb)]:
            held = int(re.search(r"hold: (\d+) lines", "\n".join(out)).group(1))
            data = tree.get(f"/home/operator/{name}-file", b"")
            ok &= data == "".join(f"line {i}\n" for i in range(1, held + 1)).encode() and held > 5
        self.check("simultaneous writes to different files: each whole and in order", ok,
                   f"{ {k: len(v) for k, v in tree.items() if k.endswith('-file')} } a={la} {ea!r} b={lb} {eb!r}")
        # Every session sshd accepts at once, all shells: the last ones
        # still get a spare, so a pipeline, a redirected command, and `ro`
        # run in each (with no spare all three were refused).
        spawned = t.spawn_count()
        holders = []
        for i in range(3):
            holders.append(self.shell_async([f"/bin/fsd-probe hold /home/operator/full-{i} 60000"]))
            t.await_spawns(spawned, 2 * (i + 1))
        rc, out, err = self.shell(["cat /etc/motd | cat", "ro /bin/fsd-probe mounts",
                                   "/bin/cat /etc/motd > /home/operator/fourth", "cat /home/operator/fourth"])
        shown = lines(out)
        for p in holders:
            self.finish(p)
        children = re.findall(r"SSH SESSION CHILD [^\n]*spares=\[([^\]]*)\]", t.output())[-4:]
        motd = ssh_absd.MOTD.decode().strip()
        self.check("four simultaneous shells: each has a spare; the fourth runs a pipeline, ro, and a redirection",
                   rc == 0 and len(children) == 4 and all(c.strip() for c in children)
                   and shown[0] == motd and shown[1].startswith("mounts: /home/operator:ro,")
                   and shown[2] == motd and err == b"",
                   f"rc={rc} spares={children} out={shown} err={err!r}")
        self.mark("SSH MULTI SESSION OK")

        # Competing create-new and rename.
        script = lambda who: ["mkdir -p /home/operator/race"] + [
            f"/bin/fsd-probe create-new /home/operator/race/{k} {who}" for k in range(8)] + [
            f"echo {who} > /home/operator/mine-{who}", f"mv /home/operator/mine-{who} /home/operator/target"]
        a, b = self.shell_async(script("A")), self.shell_async(script("B"))
        (ra, oa, ea), (rb, ob, eb) = self.finish(a), self.finish(b)
        wins = {"A": [], "B": []}
        for who, out in [("A", oa), ("B", ob)]:
            for line in lines(out):
                m = re.match(r"create-new: OK /home/operator/race/(\d+)", line)
                if m:
                    wins[who].append(int(m.group(1)))
        tree = self.device()
        owners = {k: tree.get(f"/home/operator/race/{k}") for k in range(8)}
        exactly_one = sorted(wins["A"] + wins["B"]) == list(range(8)) and all(
            owners[k] == (b"A" if k in wins["A"] else b"B") for k in range(8))
        losses = (ea + eb).decode(errors="replace").count("exit status 1")
        self.check("competing create-new: exactly one session wins each name, the loser gets AlreadyExists",
                   exactly_one and losses == 8 and b"create-new: AlreadyExists" in oa + ob,
                   f"wins={wins} owners={owners} losses={losses}")
        self.check("competing rename onto one name: both succeed in order, the name holds one whole file",
                   tree.get("/home/operator/target") in (b"A\n", b"B\n")
                   and "/home/operator/mine-A" not in tree and "/home/operator/mine-B" not in tree,
                   str(tree.get("/home/operator/target")))

        # One session disconnecting mid-write while another writes.
        spawned = t.spawn_count()
        victim = self.shell_async(["/bin/fsd-probe hold /home/operator/cut 60000"])
        t.await_spawns(spawned, 2)
        other = self.shell_async(["/bin/fsd-probe hold /home/operator/steady 5000"])
        time.sleep(4)
        victim.kill()
        victim.wait()
        ro, oo, eo = self.finish(other)
        released = self.wait_for(lambda: len(re.findall(r"SSH FS RELEASE", t.output())) >= 1)
        tree = self.device()
        cut = tree.get("/home/operator/cut", b"").decode()
        cut_lines = cut.splitlines()
        whole = cut.endswith("\n") and cut_lines == [f"line {i}" for i in range(1, len(cut_lines) + 1)]
        steady = int(re.search(r"hold: (\d+) lines", oo.decode()).group(1))
        self.check("a session killed mid-write leaves whole lines in order; the other finished its writes",
                   whole and len(cut_lines) >= 2 and ro == 0
                   and tree.get("/home/operator/steady") == "".join(f"line {i}\n" for i in range(1, steady + 1)).encode(),
                   f"cut={len(cut_lines)} whole={whole} steady={steady} rc={ro} released={released}")
        self.alive("a session killed mid-write")

        # One dying (a fault) while the other continues.
        other = self.shell_async(["/bin/fsd-probe hold /home/operator/survivor 4000"])
        time.sleep(2)
        rc, out, err = self.ssh("/bin/sshtest fault")
        ro, oo, eo = self.finish(other)
        survivor = int(re.search(r"hold: (\d+) lines", oo.decode()).group(1))
        self.check("a session dying while another writes: the other completes",
                   rc == 255 and ro == 0 and self.device().get("/home/operator/survivor")
                   == "".join(f"line {i}\n" for i in range(1, survivor + 1)).encode(), f"rc={rc} other={ro}")
        self.alive("a session fault")

        # Reconnect after churn: many sessions, some killed mid-command.
        for i in range(12):
            if i % 3 == 0:
                spawned = t.spawn_count()
                p = self.shell_async(["/bin/fsd-probe hold /home/operator/churn 30000"])
                t.await_spawns(spawned, 2)
                p.kill()
                p.wait()
            else:
                rc, out, err = self.ssh(f"/bin/fsd-probe write /home/operator/churn-{i} 1000")
                self.check(f"churn {i}", rc == 0, f"{rc} {err!r}")
        # Paced like the four-shell case above: one source (QEMU's NAT) may
        # hold two unauthenticated connections at once (`preauth_per_source`
        # in the listener record), so each connection's shell has started,
        # which is after its authentication, before the next is opened. The
        # three sessions still overlap in their writes.
        sessions = []
        for k in range(3):
            spawned = t.spawn_count()
            sessions.append(self.shell_async([f"/bin/fsd-probe write /home/operator/after-{k} 3000", "pwd"]))
            t.await_spawns(spawned, 1)
        results = [self.finish(p) for p in sessions]
        self.check("after churn three simultaneous sessions each get a slot and write",
                   all(r[0] == 0 and lines(r[1])[0].startswith("write: 3000 bytes") for r in results),
                   str([(r[0], lines(r[1]), r[2][-200:]) for r in results]))
        self.alive("churn")
        self.mark("FS MULTI SESSION COHERENCE OK")

        # -- SESSION FAILURE ISOLATION ----------------------------------------------------------
        # A path longer than any frame is refused by the client: its
        # channel keeps its framing and the shell carries on.
        rc, out, err = self.shell(["cd /" + "a" * 80000, "pwd", "echo after"], timeout=300)
        self.check("an 80000-byte path is refused without breaking the channel",
                   lines(out)[-2:] == ["/", "after"] and b"absd-sh: cd: " in err
                   and "FSD CHANNEL BROKEN" not in t.serial(),
                   f"rc={rc} out={lines(out)[-3:]} err={err[-200:]!r}")
        other = self.shell_async(["/bin/fsd-probe hold /home/operator/isolated 5000", "cat /etc/motd"])
        time.sleep(2)
        # Since the 2026-10-02 audit repair, bytes that are no frame are
        # dropped by the file server and the channel goes on (there is no
        # FSD CHANNEL BROKEN any more): the sender exits normally, its slot
        # is released, and the other session is untouched.
        released = len(re.findall(r"SSH FS RELEASE slot=", t.output()))
        rc, out, err = self.ssh("/bin/fsd-probe garbage")
        dropped = self.wait_for(lambda: len(re.findall(r"SSH FS RELEASE slot=", t.output())) > released)
        ro, oo, eo = self.finish(other)
        isolated = int(re.search(r"hold: (\d+) lines", oo.decode()).group(1))
        self.check("a session sending bytes that are no frame: they are dropped, its slot is released, the other completes",
                   rc == 0 and out == b"garbage: sent\n" and dropped
                   and "FSD CHANNEL BROKEN" not in t.serial()
                   and ro == 0 and lines(oo)[-1] == ssh_absd.MOTD.decode().strip()
                   and self.device().get("/home/operator/isolated")
                   == "".join(f"line {i}\n" for i in range(1, isolated + 1)).encode(),
                   f"rc={rc} out={out!r} released={dropped} other_rc={ro} {lines(oo)} {eo!r}")
        for i in range(12):
            rc, out, err = self.ssh(f"/bin/fsd-probe write /home/operator/rebound-{i} 100")
            if rc != 0:
                break
        self.check("every slot serves again afterwards (the broken one included)", rc == 0, f"{rc} {err!r}")
        serial = t.serial()
        self.check("the file server never failed", "FSD FAILED" not in serial, serial[-600:])
        self.mark("SESSION FAILURE ISOLATION OK")
        t.stop()

    def wait_for(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.3)
        return False

    def root_path(self):
        return self.t.root


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    target = ssh_absd.target(rest)
    matrix = FsdMatrix(target, work)
    try:
        matrix.run()
    except (sm.Failed, ssh_absd.Failed) as e:
        print(f"FSD MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    print(f"FSD MATRIX OK checks={matrix.checks}")


if __name__ == "__main__":
    main()
