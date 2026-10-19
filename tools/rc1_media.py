#!/usr/bin/env python3
"""RC1-only adapter for a curated source snapshot, not private Git history.

The original media command requires two development checkouts. This adapter
substitutes manifest-verified snapshot checks, component tree identities and
the original platform epoch. All compilation, package pins, image writing,
two-ISO comparison and validation remain in the frozen media implementation.
It never synthesizes a development commit or claims an unchanged source tree.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tomllib


def git(source, *args, env=None):
    return subprocess.run(["git", "-c", "core.fileMode=true", "-C", str(source), *args], env=env,
                          check=True, capture_output=True).stdout


def verify_snapshot(source, entry, path, kernel_copy=False):
    source, path = Path(source).resolve(), Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("snapshot must be a real directory")
    path = path.resolve()
    committed = git(source, "rev-parse", f"HEAD:{entry['path']}").decode().strip()
    if committed != entry["tree"]:
        raise ValueError("source manifest differs from the committed component tree")
    if not kernel_copy and path != source / entry["path"]:
        raise ValueError("unexpected component location")
    if kernel_copy and (path / ".git").exists():
        raise ValueError("kernel run must be a snapshot, not a different checkout")
    if git(source, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("RC1 snapshot requires SHA-1 Git object identities")
    expected = {}
    for item in git(source, "ls-tree", "-r", "-z", entry["tree"]).split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        if kind != "blob" or mode not in ("100644", "100755", "120000"):
            raise ValueError("unsupported source tree entry")
        expected[name.decode()] = (mode, object_id)
    # Explicit outputs of this RC1 media recipe only. Do not consult Git
    # filters, attributes, .git/info/exclude or global ignore configuration.
    outputs = {"build", "target"} if entry["path"] == "kernel" else {
        "target", ".staged-sysroot", "ssh/target", "ssh/tree",
        "commands", "manpages", "ports", ".ports.partial", "c/absd-c/tree"}
    output_files = set() if entry["path"] == "kernel" else set(
        "probe.elf exit-std.elf text-stats.elf panic-std.elf fixture-import.elf "
        "broker-requester.elf broker-echo.elf exec-probe.elf fsd-probe.elf "
        "sh-launch.elf netd-probe.elf compat-launch.elf sshd.elf absd-fsd.elf "
        "absd-fsd-regenerate.elf absd-enroll.elf sshtest.elf".split())
    if kernel_copy:
        output_files.add(".absd-identity")
    found = set()
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in list(dirs):
            child = Path(parent) / name
            relative = child.relative_to(path).as_posix()
            if relative in outputs:
                if child.is_symlink():
                    raise ValueError(f"build output directory is a symlink: {relative}")
                dirs.remove(name)
            elif child.is_symlink():
                dirs.remove(name)
                files.append(name)
        for name in files:
            child = Path(parent) / name
            relative = child.relative_to(path).as_posix()
            if relative not in expected:
                if relative in output_files and child.is_file() and not child.is_symlink():
                    continue
                raise ValueError(f"snapshot contains untracked source files: {relative}")
            mode, object_id = expected[relative]
            file_mode = child.lstat().st_mode
            if stat.S_ISLNK(file_mode):
                actual_mode, data = "120000", os.fsencode(os.readlink(child))
            elif stat.S_ISREG(file_mode):
                actual_mode = "100755" if file_mode & 0o111 else "100644"
                data = child.read_bytes()
            else:
                raise ValueError(f"non-regular source file: {relative}")
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if (actual_mode, actual) != (mode, object_id):
                raise ValueError(f"snapshot source bytes or mode changed: {relative}")
            found.add(relative)
    if found != set(expected):
        raise ValueError(f"snapshot source files missing: {sorted(set(expected) - found)}")
    if kernel_copy and (path / ".absd-identity").read_text().strip() != entry["commit"]:
        raise ValueError("kernel copy identity differs from the manifest")
    return entry["tree"]


def install_adapter(source, kernel):
    source = Path(source).resolve()
    raw_manifest = (source / "SOURCE-MANIFEST.toml").read_bytes()
    if raw_manifest != git(source, "show", "HEAD:SOURCE-MANIFEST.toml"):
        raise ValueError("source manifest has uncommitted changes")
    manifest = tomllib.loads(raw_manifest.decode())
    entries = {e["name"]: e for e in manifest["component"]}
    expected = {"kernel": "d208b61bcd4826181bf9f401551ab620d4eabba0",
                "platform": "0fada7ed031bd84e3a469e717c1d0be5dbefedd6"}
    if any(entries[n]["commit"] != c for n, c in expected.items()):
        raise ValueError("this adapter supports the RC1 source pair only")
    if Path(kernel).is_symlink():
        raise ValueError("kernel run must not be a symlink")
    locations = {"kernel": Path(kernel).resolve(), "platform": source / "platform"}
    for name, path in locations.items():
        verify_snapshot(source, entries[name], path, kernel_copy=name == "kernel")
    sys.path.insert(0, str(source / "platform/scripts"))
    import media
    import media_operator as operator

    def checkout_at(path, commit, what):
        if what not in entries or Path(path).resolve() != locations[what] or commit != expected[what]:
            raise media.Refused("RC1 snapshot pair or location differs")
        try:
            verify_snapshot(source, entries[what], path, kernel_copy=what == "kernel")
        except (ValueError, subprocess.CalledProcessError) as exc:
            raise media.Refused(f"RC1 snapshot changed: {exc}") from exc
        return commit

    original_git = media.git

    def snapshot_git(repo, *args):
        # The two binding reads alone need snapshot trees. All other Git
        # operations retain the frozen implementation and fail normally.
        if args == ("rev-parse", "HEAD^{tree}"):
            for name, path in locations.items():
                if Path(repo).resolve() == path:
                    checkout_at(repo, expected[name], name)
                    return (entries[name]["tree"] + "\n").encode()
        return original_git(repo, *args)

    epoch = int(datetime.datetime.fromisoformat(entries["platform"]["commit_date"]).timestamp())

    def epoch_of(path, commit):
        checkout_at(path, commit, "platform")
        return epoch

    operator.checkout_at = checkout_at
    operator.epoch_of = epoch_of
    media.git = snapshot_git
    return media, {"schema": "absd-rc1-public-snapshot-adapter/1", "source_release": manifest["release"]["id"],
                   "components": {n: {k: entries[n][k] for k in ("commit", "source_tree", "tree", "commit_date")}
                                  for n in expected}, "epoch": epoch,
                   "note": "Curated component trees, not the original development Git trees."}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("verify-snapshots", "operator-image", "operator-validate"):
        raise SystemExit("usage: rc1_media.py verify-snapshots|operator-image|operator-validate ... --kernel-run K [--out OUT]")
    source = Path(__file__).resolve().parents[1]
    try:
        kernel = sys.argv[sys.argv.index("--kernel-run") + 1]
        media, receipt = install_adapter(source, kernel)
        if sys.argv[1] == "verify-snapshots":
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 0
        out = Path(sys.argv[sys.argv.index("--out") + 1])
        result = media.main()
        if result not in (None, 0):
            return result
        (out / "PUBLIC-SOURCE-ADAPTER.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return 0
    except (ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"RC1 public snapshot refused: {exc}") from exc


if __name__ == "__main__":
    sys.exit(main())
