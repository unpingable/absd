#!/usr/bin/env python3
"""NQ fixture helper (Linux host side; no ABSD code).

`make` (driven by scripts/make-nq-fixture.sh) has the real pinned,
unpatched Linux `nq` (debug build) initialize a store, admit the real
`nq-host-helper` as the watcher `host-local`, and execute it once: one
`nq.diagnostic_execution.v2` artifact for `nq.host.load_pressure/v1`. It
then keeps the store (a `journal_mode=DELETE` copy), the artifact, a
qualify-only configuration at the guest paths, and the Linux `nq`'s
`diagnostics qualify` output.

NQ records what it sees of its host: the kernel host name, the account
that ran it, and the paths, owners and inode numbers of its helper and of
the loader and libraries the helper starts with. So the three commands run
in unprivileged namespaces (bubblewrap: user, UTS, mount and PID), where
all of that is synthetic and fixed: host name `refhost`, account
`operator` (uid and gid 1000) from a two-line account database, the tree
at /srv/absd-reference/nq, and no other file of the machine's /etc. The
namespaces are around NQ, not inside it: NQ's own helper sandbox runs
unchanged.

What stays real, and varies from one production to the next: the instants
(the store's genesis, the admission, the execution), every identity derived
from them (the store genesis id, the artifact id), the load average, CPU
count and uptime the helper read from procfs, and the device and inode
numbers, sizes, modification times and digests of the helper and of the
C library and loader under /usr. Consumers pin the artifact id and the
store genesis id; `make` prints both.
"""

import argparse
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

ROOT = "/srv/absd-reference"
HOST_LABEL = "refhost"
ACCOUNT = "operator"
ACCOUNT_ID = 1000
GUEST_CONFIG = ('schema = "nq.config.v1"\n'
                'database_path = "/nq/nq.db"\n'
                'admissions_dir = "/nq/nonexistent-admissions"\n')
EXECUTE_CONFIG = f"""\
schema = "nq.config.v1"
database_path = "{ROOT}/nq/state/nq.db"
socket_path = "{ROOT}/nq/run/nqd.sock"
admissions_dir = "{ROOT}/nq/state/admissions"
helper_runtime_dir = "{ROOT}/nq/run/helpers"

[[watchers]]
instance_id = "host-local"
carrier = "stdio"
subject = "host:local"
capability_ceiling = ["read_procfs", "read_system_info"]
checkpoint_policy = "disabled"

[watchers.command]
executable = "{ROOT}/nq/nq-host-helper"
args = []
env = {{}}
execution_account = "{ACCOUNT_ID}"
allow_same_identity_in_debug = true
working_directory = "{ROOT}/nq"

[watchers.profile]
id = "nq.host"
version = 1

[watchers.scope]
kind = "host"
value = {{ id = "local" }}

[watchers.vantage]
kind = "local"
value = {{}}
"""


def fail(message):
    sys.exit(f"NQ FIXTURE FAILED: {message}")


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def synthetic_host(work, nq):
    """The bubblewrap command line under which `nq` sees only the synthetic
    host: an empty root with the machine's /usr read-only, a two-line
    account database, and the production tree."""
    etc = work / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0:root:/root:/usr/sbin/nologin\n"
                                f"{ACCOUNT}:x:{ACCOUNT_ID}:{ACCOUNT_ID}:{ACCOUNT}:{ROOT}/nq:/bin/sh\n")
    (etc / "group").write_text(f"root:x:0:\n{ACCOUNT}:x:{ACCOUNT_ID}:\n")
    return ["bwrap", "--die-with-parent", "--unshare-user", "--uid", str(ACCOUNT_ID), "--gid", str(ACCOUNT_ID),
            "--unshare-uts", "--hostname", HOST_LABEL, "--unshare-pid", "--tmpfs", "/",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--ro-bind", str(etc / "passwd"), "/etc/passwd", "--ro-bind", str(etc / "group"), "/etc/group",
            "--dir", f"{ROOT}/bin", "--ro-bind", str(nq), f"{ROOT}/bin/nq",
            "--bind", str(work / "nq"), f"{ROOT}/nq",
            "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LOGNAME", ACCOUNT,
            "--setenv", "HOME", f"{ROOT}/nq", "--chdir", f"{ROOT}/nq",
            f"{ROOT}/bin/nq", "--config", f"{ROOT}/nq/nq.toml"]


def qualify(nq, out, artifact_id):
    """The Linux `nq` on the kept files in a read-only directory, as the NQ
    matrix runs it."""
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch) / "nq"
        base.mkdir()
        shutil.copy(out / "store" / "nq.db", base / "nq.db")
        (base / "nq.toml").write_text(GUEST_CONFIG.replace('"/nq/', f'"{base}/'))
        os.chmod(base / "nq.db", 0o444)
        os.chmod(base, 0o555)
        try:
            return subprocess.run([str(nq), "--config", str(base / "nq.toml"), "--json", "diagnostics", "qualify",
                                   artifact_id], stdin=subprocess.DEVNULL, capture_output=True)
        finally:
            os.chmod(base, 0o755)


def identifying():
    """Names of the producing machine that must not reach the fixture."""
    account = pwd.getpwuid(os.getuid())
    names = {socket.gethostname(), socket.gethostname().split(".")[0], account.pw_name, account.pw_dir,
             os.environ.get("TMPDIR", ""), str(pathlib.Path.cwd())}
    return {name.encode() for name in names if len(name) >= 3 and name not in (HOST_LABEL, ACCOUNT, "/tmp")}


def make(args):
    nq = pathlib.Path(args.nq).resolve()
    helper = pathlib.Path(args.helper).resolve()
    work = pathlib.Path(args.work).resolve()
    out = pathlib.Path(args.out).resolve()
    require(not out.exists(), f"refusing to overwrite {out}")
    work.mkdir(parents=True)
    # NQ refuses a helper runtime directory whose ancestors others can write.
    tree = work / "nq"
    for directory in (tree, tree / "state", tree / "run"):
        directory.mkdir()
        directory.chmod(0o755)
    shutil.copyfile(helper, tree / "nq-host-helper")
    (tree / "nq-host-helper").chmod(0o755)
    (tree / "nq.toml").write_text(EXECUTE_CONFIG)
    command = synthetic_host(work, nq)

    def run(*arguments):
        result = subprocess.run(command + list(arguments), stdin=subprocess.DEVNULL, capture_output=True)
        require(result.returncode == 0, f"nq {' '.join(arguments)}: exit {result.returncode}: "
                                        f"{result.stderr.decode(errors='replace')[-2000:]}")
        return result.stdout

    run("init")
    admitted = json.loads(run("watcher", "admit", "host-local"))
    require(admitted["outcome"] == "activated", f"watcher admission: {admitted}")
    artifact_bytes = run("--json", "diagnostics", "execute", "host-local").rstrip(b"\n")
    artifact = json.loads(artifact_bytes)
    require(artifact["schema"] == "nq.diagnostic_execution.v2" and artifact["question"]["id"] == "nq.host.load_pressure",
            f"unexpected artifact {artifact.get('schema')}")
    require(artifact_bytes == json.dumps(artifact, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False).encode(), "the artifact is not canonical bytes")

    (out / "store").mkdir(parents=True)
    (out / "reference").mkdir()
    store = out / "store" / "nq.db"
    for path in sorted((tree / "state").glob("nq.db*")):
        if path.is_file():
            shutil.copyfile(path, out / "store" / path.name)
    # A single file that a read-only mount can open: fold the WAL in.
    database = sqlite3.connect(store)
    require(database.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete", "cannot leave WAL mode")
    require(database.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "store integrity")
    database.close()
    require(sorted(path.name for path in (out / "store").iterdir()) == ["nq.db"], "the store is not one file")
    (out / "artifact.json").write_bytes(artifact_bytes)
    (out / "nq.toml").write_text(GUEST_CONFIG)

    answer = qualify(nq, out, artifact["artifact_id"])
    require(answer.returncode == 0, f"nq qualify: {answer.stderr.decode(errors='replace')[-2000:]}")
    provenance = json.loads(answer.stdout)
    require(provenance["disposition"] == "admitted_report" and
            provenance["artifact"]["canonical_bytes_sha256"] == f"sha256:{sha256(artifact_bytes)}",
            "qualify does not admit the kept artifact")
    (out / "reference" / "provenance.json").write_bytes(answer.stdout)
    source_id = provenance["source"]["source_id"]
    require(artifact["producer"]["node_id"] == source_id, "the artifact's producer is not this store")

    # Nothing of the producing machine's identity, and the synthetic one.
    data = store.read_bytes()
    for name in identifying():
        require(name not in data, "the store names the producing machine or its account")
    require(f'"hostname":"{HOST_LABEL}"'.encode() in data and f'"login_hint":"{ACCOUNT}"'.encode() in data,
            "the store does not hold the synthetic host and account")

    files = {}
    for relative in ("artifact.json", "nq.toml", "reference/provenance.json", "store/nq.db"):
        content = (out / relative).read_bytes()
        files[relative] = {"bytes": len(content), "sha256": sha256(content)}
    manifest = {
        "schema": "absd.nq-fixture/v1",
        "nq_source": "NQ-NG",
        "nq_commit": args.nq_commit,
        "nq_tree": args.nq_tree,
        "profile_digest": args.profile_digest,
        "origin": "scripts/make-nq-fixture.sh",
        "writer": "real nq debug build in a synthetic host (scripts/nq_fixture.py): init, watcher admit host-local "
                  "(real nq-host-helper, allow_same_identity_in_debug), --json diagnostics execute host-local; "
                  "store copied with journal_mode=DELETE",
        "reference": "stdout of the same Linux nq: nq --config <nq.toml> --json diagnostics qualify <artifact_id>",
        "host": {"hostname": HOST_LABEL, "account": ACCOUNT, "uid": ACCOUNT_ID, "root": f"{ROOT}/nq"},
        "binaries": {"nq": sha256(nq.read_bytes()), "nq-host-helper": sha256(helper.read_bytes())},
        "artifact_id": artifact["artifact_id"],
        "source_id": source_id,
        "started_at": artifact["started_at"],
        "completed_at": artifact["completed_at"],
        "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    print(f"NQ FIXTURE artifact={artifact['artifact_id']} source={source_id} "
          f"completed_at={artifact['completed_at']} manifest={sha256((out / 'manifest.json').read_bytes())}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("make")
    for name in ("--nq", "--helper", "--work", "--out", "--nq-commit", "--nq-tree", "--profile-digest"):
        m.add_argument(name, required=True)
    make(parser.parse_args())


if __name__ == "__main__":
    main()
