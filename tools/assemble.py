#!/usr/bin/env python3
"""Assemble the ABSD public source tree from pinned development revisions.

    assemble.py build OUT [--config assembly.toml] [--report DIR]
                          [--require-publishable]
    assemble.py commit OUT -m MESSAGE [--staging]

`build` replaces the contents of OUT (keeping OUT/.git) with the tree the
configuration describes, writes OUT/SOURCE-MANIFEST.toml and
OUT/THIRD-PARTY.md, and writes a report beside it. The report keeps these
questions apart and never folds them into one answer:

    PINS          do the components agree about each other's revisions
    PRIVATE       host names, home paths, addresses, credentials in OUT
    SOURCE        each component's own scripts/provenance.py verdict
    REPRODUCIBLE  does a second assembly give the same tree
    QUALIFICATION what the release itself says was not run on it
    PUBLISHABLE   the four checks above, a committed assembler, nothing held

PUBLISHABLE means the tree is safe to publish as it describes itself. It is
not a statement that any qualification suite passed: what was not run is
listed under QUALIFICATION, written into the manifest and never counted as
a pass.

OUT carries NOT-FOR-PUBLICATION.md from the first moment of a build until
the end of one that found the tree publishable. `commit` records only the
tree the last build produced, and a tree that is not publishable only with
--staging and never on `main`.

Licensing decisions belong to each component's provenance.toml and
scripts/provenance.py; this tool runs them and carries what they record.
It adds no inventory of its own. Standard library only.
"""

import argparse
import fnmatch
import importlib.util
import io
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # importing a component's tool must not add files to the tree
MARKER = "NOT-FOR-PUBLICATION.md"
STAMP = "ABSD_ASSEMBLY"  # in OUT/.git: the tree the last build produced, and its verdict
GENERATED = ["SOURCE-MANIFEST.toml", "THIRD-PARTY.md", "tools/assemble.py", "tools/assembly.toml", MARKER]

# What must not reach a public tree. The assembling machine is a development
# machine, so its own user, home and host name are patterns without any
# configuration. A private-pattern file (scripts/provenance.py's, optional)
# adds more; the report says whether one was read. `/home/...` alone is not
# a finding: ABSD has a /home. 10.0.2.0/24 is QEMU's user network.
USER = pwd.getpwuid(os.getuid()).pw_name
HOST = socket.gethostname().split(".")[0]
GENERIC = [
    ("home-path", re.compile(r"/home/(?!operator/)[a-z][a-z0-9_-]*/\.[a-z]|/Users/[A-Za-z]|" + re.escape(str(Path.home())))),
    ("assembler-user", re.compile(rf"(?<![A-Za-z0-9]){re.escape(USER)}(?![A-Za-z0-9])", re.I)),
    ("assembler-host", re.compile(rf"(?<![A-Za-z0-9]){re.escape(HOST)}(?![A-Za-z0-9])", re.I)),
    ("development-path", re.compile(r"/data/git|\.campaign-local|\.lanes/")),
    ("private-address", re.compile(
        r"(?<![\d.])(?:192\.168\.\d{1,3}\.\d{1,3}|10\.(?!0\.2\.)\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")),
    ("project-board", re.compile(r"github\.com/users/[\w-]+/projects/")),
]


class Problem(Exception):
    pass


def git(*args, cwd=None, env=None, text=True, check=True, data=None):
    run = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=text, input=data)
    if check and run.returncode:
        raise Problem(f"git {' '.join(args)}: {run.stderr.strip() if text else run.stderr!r}")
    return run.stdout.strip() if text else run.stdout


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) or (p.endswith("/") and path.startswith(p)) for p in patterns)


def tree_id(directory, without=()):
    """Git tree id of a plain directory, computed in a throwaway repository
    with no user, system or attribute configuration."""
    with tempfile.TemporaryDirectory() as scratch:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_DIR=scratch + "/g", GIT_WORK_TREE=str(directory), GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_CONFIG_NOSYSTEM="1", GIT_ATTR_NOSYSTEM="1")
        settings = ["-c", "core.fileMode=true", "-c", "core.autocrlf=false", "-c", "core.symlinks=true",
                    "-c", "core.attributesFile=/dev/null"]
        git("init", "-q", env=env)
        git(*settings, "add", "-A", "-f", ".", env=env, cwd=directory)
        for name in without:
            git(*settings, "rm", "-q", "--cached", "--ignore-unmatch", "--", name, env=env, cwd=directory)
        return git("write-tree", env=env)


def tree_of_commit(repo, commit, keep):
    """Tree id of the commit's files for which keep(name) holds, by way of a
    scratch index: what an archive of them must hash to."""
    entries = [e for e in git("ls-tree", "-r", "-z", commit, cwd=repo).split("\0") if e and keep(e.split("\t", 1)[1])]
    with tempfile.TemporaryDirectory() as scratch:
        env = dict(os.environ, GIT_INDEX_FILE=scratch + "/index")
        git("update-index", "-z", "--index-info", cwd=repo, env=env, data="\0".join(entries) + "\0")
        return git("write-tree", cwd=repo, env=env), len(entries)


def extract(component, out, pinned):
    """One component: the pinned commit's files, less what is left out, under
    dest. A component with `files_from` is exactly the files another
    component's list names (a workload the platform reads only in part)."""
    repo, rev, dest = component["repo"], component["commit"], out / component["dest"]
    commit = git("rev-parse", f"{rev}^{{commit}}", cwd=repo)
    if commit != rev:
        raise Problem(f"{component['name']}: commit must be a full id, {rev} resolves to {commit}")
    exclude, keep, listed = component.get("exclude", []), component.get("keep", []), None
    if "files_from" in component:
        if exclude or keep:
            raise Problem(f"{component['name']}: a listed component takes no exclusions")
        listed = set(pinned(component["files_from"]).splitlines())
        wanted = lambda name: name in listed
    else:
        wanted = lambda name: not (matches(name, exclude) and not matches(name, keep))
    data = git("archive", "--format=tar", commit, cwd=repo, text=False)
    dropped, members = [], []
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar:
            if member.isdir() or member.name == "pax_global_header":
                continue
            (members if wanted(member.name) else dropped).append(member)
        tar.extractall(dest, members=members, filter="tar")
    expected, count = tree_of_commit(repo, commit, wanted)
    record = {
        "name": component["name"], "role": component["role"], "source": component["source"],
        "commit": commit, "commit_date": git("show", "-s", "--format=%cI", commit, cwd=repo),
        "source_tree": git("rev-parse", f"{commit}^{{tree}}", cwd=repo),
        "path": component["dest"], "tree": tree_id(dest), "files": len(members),
        "excluded_files": len(dropped), "exclude": exclude, "keep": keep,
        "files_from": component.get("files_from", ""), "license": component.get("license", ""),
        "note": component.get("note", ""),
    }
    # What was written must be the commit's own files and nothing else,
    # whatever an archive attribute or the extraction might have done.
    if record["tree"] != expected or count != len(members):
        raise Problem(f"{component['name']}: wrote tree {record['tree']} ({len(members)} files); the commit's "
                      f"files less the exclusions are {expected} ({count} files)")
    if listed is not None:
        want = pinned(component["tree_from"]).strip()
        if record["tree"] != want or len(members) != len(listed):
            raise Problem(f"{component['name']}: listed files give tree {record['tree']}, "
                          f"{component['tree_from']} pins {want}")
    return record, [m.name for m in dropped]


def pin_checks(config, out):
    """Each `[[pin]]`: a file in the assembled tree must name a component's commit."""
    rows, by_name = [], {c["name"]: c for c in config["component"]}
    for pin in config.get("pin", []):
        commit = by_name[pin["component"]]["commit"]
        found = re.search(pin["pattern"], (out / pin["file"]).read_text())
        named = found.group(1) if found else None
        rows.append(("ok" if named == commit else "DIFFERS", pin["component"], pin["file"], named, commit))
    return rows


def tool(path):
    spec = importlib.util.spec_from_file_location("absd_provenance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_public(component):
    """Whether the component's commit is on a branch of a remote whose URL is
    the public source the configuration names (as far as the local clone's
    remote-tracking refs show; nothing is fetched)."""
    source = component["source"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    for line in git("remote", "-v", cwd=component["repo"]).splitlines():
        name, url = line.split()[:2]
        if url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1] != source:
            continue
        if git("branch", "-r", "--contains", component["commit"], "--list", f"{name}/*", cwd=component["repo"]):
            return True
    return False


def private_scan(config, out, prov):
    """Generic patterns, the optional private-pattern file, credential shapes.
    Binary files are searched as bytes for the same patterns."""
    extra = prov.private_patterns()
    patterns = GENERIC + [("private-name", re.compile(p.pattern, p.flags | re.I)) for p in (extra or [])]
    by_name = {c["name"]: c for c in config["component"]}
    accepted = []
    for rule in config.get("accept", []):
        if "public" in rule and not is_public(by_name[rule["public"]]):
            continue  # the claim "already public" does not hold: the rule accepts nothing
        accepted.append(dict(rule, used=0))
    hits, waived = [], []
    for path in sorted(p for p in out.rglob("*") if p.is_file() and ".git" not in p.relative_to(out).parts):
        rel = str(path.relative_to(out))
        if rel == MARKER:
            continue
        data = path.read_bytes()
        if prov.is_binary(data):
            kinds = ["credential"] if prov.KEY_NAMES.search(rel) else []
            lines = data.decode("latin-1").split("\n")
        else:
            text = data.decode("utf-8", "replace")
            kinds = ["credential"] if prov.SECRETS.search(text) else []
            lines = text.splitlines()
        counts = {}
        for kind, pattern in patterns:
            n = sum(1 for line in lines if pattern.search(line))
            if n:
                counts[kind] = n
        for kind in kinds:
            counts[kind] = counts.get(kind, 0) + 1
        for kind, n in counts.items():
            rule = next((a for a in accepted if kind in a["kinds"] and matches(rel, a["paths"])), None)
            if rule:
                rule["used"] += n
            (waived if rule else hits).append((rel, kind, n, rule["reason"] if rule else ""))
    # An accepted rule states how many lines it was written for; more is new.
    over = [f"{a['reason']}: {a['used']} lines, accepted for {a['lines']}" for a in accepted if a["used"] > a["lines"]]
    return hits, waived, over, extra is not None


def source_verdicts(config):
    """Each component's own readiness report, run in a clean checkout of its
    pin. An open obligation the configuration lists under `discharged` is
    one the development repository cannot close and the assembled tree
    answers; every other open one keeps SOURCE from clearing."""
    rows = []
    discharged = {(d["component"], d["obligation"]): d["reason"] for d in config.get("discharged", [])}
    for component in config["component"]:
        if not component.get("readiness"):
            continue
        with tempfile.TemporaryDirectory() as scratch:
            clone = Path(scratch) / "c"
            git("clone", "-q", "--shared", "--no-checkout", component["repo"], str(clone))
            git("checkout", "-q", "--detach", component["commit"], cwd=clone)
            run = subprocess.run([sys.executable, "scripts/provenance.py", "report", "--require", "source"],
                                 cwd=clone, capture_output=True, text=True)
        verdicts = dict(re.findall(r"^## ([A-Z_]+): ([A-Z_]+)", run.stdout, re.M))
        if "SOURCE_PUBLICATION" not in verdicts:
            raise Problem(f"{component['name']}: provenance.py report gave no verdict:\n{run.stderr[-800:]}")
        section = re.search(r"^## SOURCE_PUBLICATION.*?\n(.*?)(?=^## |\Z)", run.stdout, re.M | re.S).group(1)
        blocking = section.split("### For counsel")[0].split("### Notes")[0]
        open_items, answered = [], []
        for bullet in re.findall(r"^- (.*)$", blocking, re.M):
            if re.match(r"File-level licensing .*: pass;", bullet):
                continue
            found = re.match(r"([A-Z][A-Z0-9-]+): ", bullet)
            reason = discharged.get((component["name"], found.group(1))) if found else None
            (answered if reason else open_items).append((bullet, reason))
        rows.append((component["name"], verdicts, open_items, answered))
    return rows


def third_party(config, out, records):
    """THIRD-PARTY.md from each component's provenance.toml: what is in this
    tree that is not first-party, under what terms, from where."""
    lines = ["# Third-party material in this source tree", "",
             "Generated from each component's `provenance.toml`, which is the record to",
             "correct. It lists files carried in this tree. Libraries fetched at build time",
             "are listed per image in each component's `provenance/inventory/`.", ""]
    for record in records:
        base = out / record["path"]
        if record["files_from"]:
            texts = sorted(p.name for p in base.iterdir() if re.match(r"(LICEN[CS]E|NOTICE|COPYING|THIRD_PARTY)", p.name))
            lines += [f"## `{record['path']}/`", "",
                      f"{record['files']} files of {record['source']} at `{record['commit'][:12]}`, "
                      f"{record['license']}. Its own files state the terms: {', '.join(texts) or 'none found'}.", ""]
            continue
        inventory = base / "provenance.toml"
        if not inventory.exists():
            continue
        rules = [r for r in tomllib.loads(inventory.read_text()).get("files", [])
                 if r.get("class") not in (None, "first-party")]
        files = [str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()]
        rows = []
        for rule in rules:
            paths = rule["path"] if isinstance(rule["path"], list) else [rule["path"]]
            present = [p for p in paths if any(fnmatch.fnmatchcase(f, p.replace("**", "*")) for f in files)]
            if not present:
                continue
            rows.append("| " + " | ".join([
                "<br>".join(f"`{record['path']}/{p}`" for p in present), rule.get("class", ""),
                str(rule.get("license", "")),
                str(rule.get("upstream-license", "")),
                str(rule.get("upstream", rule.get("origin", ""))).replace("|", "/"),
            ]) + " |")
        if rows:
            lines += [f"## `{record['path']}/`", "",
                      "| Path | Class | Licence | Upstream licence | Upstream |", "|---|---|---|---|---|", *rows, ""]
    (out / "THIRD-PARTY.md").write_text("\n".join(lines))


def manifest(config, records):
    def q(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    release = config["release"]
    lines = ["# What this source tree was assembled from. Generated; do not edit.",
             "# `tree` is the Git tree id of `path` in this repository:",
             "#     git rev-parse HEAD:<path>",
             "# It is the tree of the named commit's files less those `exclude` names",
             "# (and `keep` restores), or, where `files_from` is given, of exactly the",
             "# files that list names. Nothing else is changed.", "",
             "[release]", f"id = {q(release['id'])}", f"date = {q(release['date'])}",
             f"status = {q(release['status'])}", f"assembler = {q(config['_assembler'])}",
             "# Qualification that was NOT run on this release. An empty list would mean",
             "# everything the README names was run; nothing listed here is a pass.",
             "not_run = [" + ", ".join(q(item) for item in config["not_run"]) + "]", ""]
    if config.get("toolchain"):
        lines.append("[toolchain]")
        lines += [f"{key} = {q(value)}" for key, value in config["toolchain"].items()]
        lines.append("")
    for record in records:
        lines.append("[[component]]")
        for key in ("name", "role", "source", "commit", "commit_date", "source_tree", "path", "tree"):
            lines.append(f"{key} = {q(record[key])}")
        lines.append(f"files = {record['files']}")
        lines.append(f"excluded_files = {record['excluded_files']}")
        if record["license"]:
            lines.append(f"license = {q(record['license'])}")
        if record["files_from"]:
            lines.append(f"files_from = {q(record['files_from'])}")
        else:
            lines.append("exclude = [" + ", ".join(q(p) for p in record["exclude"]) + "]")
            if record["keep"]:
                lines.append("keep = [" + ", ".join(q(p) for p in record["keep"]) + "]")
        if record["note"]:
            lines.append(f"note = {q(record['note'])}")
        lines.append("")
    return "\n".join(lines)


def assemble(config, out):
    for entry in out.iterdir() if out.exists() else []:
        if entry.name != ".git":
            shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("# Not for publication\n\nAn assembly is in progress or did not finish.\n")
    by_name = {c["name"]: c for c in config["component"]}

    def pinned(spec):
        """`component:path`: that file at the component's pinned commit."""
        name, path = spec.split(":", 1)
        return git("show", f"{by_name[name]['commit']}:{path}", cwd=by_name[name]["repo"]) + "\n"

    records, dropped = [], {}
    for component in config["component"]:
        record, gone = extract(component, out, pinned)
        records.append(record)
        dropped[component["name"]] = gone
    overlay = HERE / config.get("overlay", "overlay")
    for path in sorted(p for p in overlay.rglob("*") if p.is_file()):
        target = out / path.relative_to(overlay)
        if target.exists() or str(path.relative_to(overlay)) in GENERATED:
            raise Problem(f"overlay file collides with the tree: {target.relative_to(out)}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    for name in GENERATED[:-1]:
        if (out / name).exists():
            raise Problem(f"a component or the overlay already has {name}")
    # The tool and its configuration travel with the tree they produced.
    (out / "tools").mkdir(exist_ok=True)
    shutil.copy2(Path(__file__).resolve(), out / "tools/assemble.py")
    shutil.copy2(config["_config_path"], out / "tools/assembly.toml")
    for path in sorted(overlay.rglob("*.md")):
        for named in re.findall(r"`((?:kernel|platform|examples|tools|docs)/[^`\s*<>]+)`", path.read_text()):
            if not (out / named).exists():
                raise Problem(f"{path.relative_to(overlay)} names {named}, which is not in the tree")
    third_party(config, out, records)
    (out / "SOURCE-MANIFEST.toml").write_text(manifest(config, records))
    return records, dropped


def assembler_identity():
    """The commit of this repository, or why the assembly is not a function
    of committed inputs."""
    status = git("status", "--porcelain", cwd=HERE)
    commit = git("rev-parse", "HEAD", cwd=HERE)
    return commit if not status else f"{commit} with uncommitted changes"


def build(args):
    config = tomllib.loads(Path(args.config).read_text())
    # Where each component's development repository is on this machine: a
    # local, untracked file, so the configuration itself can be published.
    repos = tomllib.loads(Path(args.repos).read_text())
    for component in config["component"]:
        if component["name"] not in repos:
            raise Problem(f"{args.repos} names no repository for {component['name']}")
        component["repo"] = os.path.expanduser(repos[component["name"]])
    config["_config_path"] = args.config
    config["_assembler"] = assembler_identity()
    out = Path(args.out).resolve()
    if not (out / ".git").exists():
        out.mkdir(parents=True, exist_ok=True)
        git("init", "-q", "-b", "staging", cwd=out)
    stamp = out / ".git" / STAMP
    stamp.unlink(missing_ok=True)
    records, dropped = assemble(config, out)
    first = tree_id(out, without=[MARKER])
    with tempfile.TemporaryDirectory() as scratch:
        assemble(config, Path(scratch) / "again")
        second = tree_id(Path(scratch) / "again", without=[MARKER])

    prov_path = next(out / c["dest"] / "scripts/provenance.py" for c in config["component"] if c.get("readiness"))
    pins = pin_checks(config, out)
    hits, waived, over, had_private = private_scan(config, out, tool(prov_path))
    sources = source_verdicts(config)

    for key in ("held", "not_run"):
        if not isinstance(config.get(key), list):
            raise Problem(f"the configuration must have a top-level `{key}` list (empty when there is nothing)")
    held = list(config["held"])
    if "uncommitted" in config["_assembler"]:
        held.append("the assembler, its configuration or the overlay has uncommitted changes")
    ok = {
        "PINS": all(row[0] == "ok" for row in pins),
        "PRIVATE": not hits and not over,
        "SOURCE": all(not open_items for _, _, open_items, _ in sources),
        "REPRODUCIBLE": first == second,
    }
    publishable = all(ok.values()) and not held

    text = [f"# Assembly report: {config['release']['id']}", "",
            f"Tree {first} (without {MARKER}), assembler {config['_assembler']}. "
            "A mechanical report; it authorizes nothing.", "", "## Components", ""]
    for r in records:
        text.append(f"- {r['path']}/: {r['source']} {r['commit']}, {r['files']} files, {r['excluded_files']} left out"
                    + (f" (listed by {r['files_from']})" if r["files_from"] else "") + f", tree {r['tree']}")
    text += ["", f"## PINS: {'CONSISTENT' if ok['PINS'] else 'INCONSISTENT'}", ""]
    text += [f"- {s}: {f} names {n}; {c} is assembled at {want}" for s, c, f, n, want in pins]
    text += ["", f"## PRIVATE: {'NONE_FOUND' if ok['PRIVATE'] else 'FOUND'}", "",
             f"Private-pattern file read: {'yes' if had_private else 'no (generic patterns only)'}."
             f" Unaccepted: {sum(n for _, _, n, _ in hits)} lines in {len({h[0] for h in hits})} files."
             f" Accepted by rule: {sum(n for _, _, n, _ in waived)} lines in {len({h[0] for h in waived})} files.", ""]
    text += [f"- {rel}: {kind} x{n}" for rel, kind, n, _ in hits]
    text += [f"- over the accepted count: {line}" for line in over]
    if waived:
        text += ["", "Accepted:", ""]
        reasons = {}
        for rel, kind, n, reason in waived:
            reasons.setdefault(reason, []).append(f"{rel} ({kind} x{n})")
        for reason, where in reasons.items():
            text += [f"- {reason}: " + "; ".join(where)]
    text += ["", f"## SOURCE: {'NO_KNOWN_BLOCKER' if ok['SOURCE'] else 'NOT_READY'}", ""]
    for name, verdicts, open_items, answered in sources:
        text += [f"- {name}: its own report says " + ", ".join(f"{k} {v}" for k, v in verdicts.items())]
        text += [f"  - open: {bullet}" for bullet, _ in open_items]
        text += [f"  - answered by this assembly ({reason}): {bullet}" for bullet, reason in answered]
    text += ["", f"## REPRODUCIBLE: {'SAME_TREE' if ok['REPRODUCIBLE'] else 'DIFFERS'}", "",
             f"Two assemblies: {first} and {second}. This is the source tree only, not built artifacts.", ""]
    text += [f"## QUALIFICATION: {'NOT_RUN' if config['not_run'] else 'NOTHING_OUTSTANDING'}", "",
             "What the release states was not run on it (in its manifest and README). Not a check, never a pass.", ""]
    text += [f"- not run: {item}" for item in config["not_run"]]
    text += ["", f"## PUBLISHABLE: {'YES' if publishable else 'NO'}", "",
             "Safe to publish as it describes itself; says nothing about qualification.", ""]
    text += [f"- held: {h}" for h in held]
    text += [f"- {name} is not clear" for name, good in ok.items() if not good]
    report = Path(args.report or f"{out}-report")
    report.mkdir(parents=True, exist_ok=True)
    (report / "ASSEMBLY.md").write_text("\n".join(text) + "\n")
    (report / "excluded.txt").write_text(
        "".join(f"{name}\t{path}\n" for name, paths in dropped.items() for path in paths))

    if publishable:
        (out / MARKER).unlink()
    else:
        why = [f"- {name}: not clear" for name, good in ok.items() if not good] + [f"- {h}" for h in held]
        (out / MARKER).write_text(
            "# Not for publication\n\nThis tree is a staging assembly. It must not be published or\n"
            "redistributed: the checks below have not passed.\n\n" + "\n".join(why) + "\n")
    stamp.write_text(f"{first} {'publishable' if publishable else 'staging'}\n")
    print("\n".join(line for line in text if line.startswith("## ")))
    print(f"report: {report}/ASSEMBLY.md")
    if args.require_publishable and not publishable:
        return 1
    return 0 if ok["PRIVATE"] and ok["REPRODUCIBLE"] else 2


def commit(args):
    """Record the tree the last build produced, and nothing else."""
    out = Path(args.out).resolve()
    stamp = out / ".git" / STAMP
    if not stamp.exists():
        raise Problem("no completed build of this tree (run build first)")
    tree, verdict = stamp.read_text().split()
    if tree_id(out, without=[MARKER]) != tree:
        raise Problem("the tree has changed since the last build")
    branch = git("symbolic-ref", "--short", "HEAD", cwd=out)
    if verdict != "publishable" or (out / MARKER).exists():
        if not args.staging:
            raise Problem(f"this tree is a staging assembly ({MARKER}); use --staging to record it locally")
        if branch == "main":
            raise Problem("a staging assembly is never committed on main")
    elif args.staging:
        raise Problem("this tree is publishable; --staging is for one that is not")
    elif branch != "main":
        raise Problem(f"a release is committed on main, not {branch}")
    else:
        # A repository that ever held a staging assembly holds whatever that
        # assembly contained. A release goes in one that never did.
        other = [r for r in git("for-each-ref", "--format=%(refname)", cwd=out).splitlines()
                 if r != "refs/heads/main" and not r.startswith("refs/tags/absd-")]
        if other:
            raise Problem(f"this repository has refs besides main and release tags ({other[0]}): "
                          "commit a release in a fresh repository")
    git("add", "-A", "-f", ".", cwd=out)
    for entry in tomllib.loads((out / "SOURCE-MANIFEST.toml").read_text())["component"]:
        staged = git("write-tree", f"--prefix={entry['path']}/", cwd=out)
        if staged != entry["tree"]:
            raise Problem(f"{entry['path']}/ is tree {staged}, the manifest says {entry['tree']}")
    git("commit", "-q", "-m", args.message, cwd=out)
    print(git("log", "-1", "--format=%H %s", cwd=out))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.add_argument("out")
    p.add_argument("--config", default=str(HERE / "assembly.toml"))
    p.add_argument("--repos", default=str(HERE / "repos.local.toml"))
    p.add_argument("--report")
    p.add_argument("--require-publishable", action="store_true")
    p = sub.add_parser("commit")
    p.add_argument("out")
    p.add_argument("-m", "--message", required=True)
    p.add_argument("--staging", action="store_true")
    args = parser.parse_args()
    try:
        return {"build": build, "commit": commit}[args.command](args)
    except Problem as problem:
        print(f"assemble: {problem}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
