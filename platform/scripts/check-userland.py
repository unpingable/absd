#!/usr/bin/env python3
"""Host checks of the base userland ports (userland/README.md, "Checks").

Run by scripts/build-userland.sh after both builds. For every port in
userland/Makefile's UTILS:

  gate     the kit's ELF gate, scripts/check-c-elf.py --map, on the ABSD ELF;
  demand   the names the port's ABSD objects and the libutil/libutf members
           they pull reference and do not define, classified as
           scripts/userland-demand.py classifies: every name must be defined
           by Picolibc, the kit or the adapter (no MISSING, no name refused
           at link time); names the adapter answers with a run-time refusal
           are listed. The set is compared with the port's rows in
           userland/DEMAND.tsv (the unpatched probe) and with the demand of
           the host REFERENCE objects (gcc, glibc); the differences are
           written to <build>/demand/<port>.txt and counted;
  host     every userland/cases.tsv case run on the REFERENCE binary
           (argv[0] /bin/<utility> as on ABSD, ruling D-21; empty
           environment, fresh directory of
           FIXTURES) must match its pin in userland/expected/ (status,
           stdout, stderr and, when the case created, changed or removed
           a file in its directory, a "--- files" section naming each
           with its new content). --update writes the pins instead.

The ABSD ELFs are not run: the kit has no host-run route. A passing check
says the ports are well-formed, reproducible, fully resolved, and that the
cases' expected outputs are pinned; it does not say the ABSD binaries behave
like the reference. That is the guest qualification's (T5) to show, with
userland/divergences.tsv naming the cases whose ABSD outcome must differ.

Prints `USERLAND BUILD OK ports=<n> reproducible=2 gate=<n> unresolved=0
host_cases=<n> guest=unverified`.
"""
import importlib.util, io, json, os, shlex, shutil, subprocess, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("userland_demand", ROOT / "scripts" / "userland-demand.py")
ud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ud)
OUT = Path(os.environ.get("ABSD_USERLAND_BUILD", ud.CAMP / "userland-build"))
UPDATE = "--update" in sys.argv[1:]

# Every case's working directory. older.txt is older than words.txt
# (mtimes set explicitly: test -nt); dir/ is an empty directory.
FIXTURES = {
    "words.txt": b"b\na\na\nc\nc\nc\n",
    "words2.txt": b"b\na\nx\nc\nc\nc\n",
    "words-short.txt": b"b\na\na\n",
    "lines.txt": b"".join(b"line %d.%d\n" % (i, i) for i in range(1, 7)),
    "nums.txt": b"10\n9\n100\n-3\n9\n",
    "passwd.txt": b"root:x:0:0:root:/root:/bin/sh\noperator:x:1000:1000:operator:/home/operator:/bin/absd-sh\n"
                  b"daemon:x:1:1:daemon:/:/bin/false\n",
    "bin.dat": bytes(range(0, 40)),
    "empty.txt": b"",
    "basic.ustar": (ROOT / "userland/tar-vectors/basic.ustar").read_bytes(),
    "bad.ustar": b"invalid archive",
    "zero48.dat": bytes(48),
    "high.dat": bytes([128,255]),
    "older.txt": b"old\n",
    # one entry per directory level, so a traversal's order is the same on
    # every filesystem (find; readdir order is the server's, CPA-032)
    "tree/sub/leaf.txt": b"leaf\n",
    # ed command scripts (fed as stdin)
    "ed-new.ed": b"a\n#include <stdio.h>\nint main(void) { puts(\"hi\"); return 0; }\n.\nw hello.c\nq\n",
    "ed-edit.ed": b"2,3d\n1s/line/LINE/\n$a\nadded\n.\n,n\nw\nq\n",
    "ed-global.ed": b"g/c/s//C/\n,p\nQ\n",
    "ed-undo.ed": b"1d\nu\n1p\nQ\n",
    "ed-read.ed": b"r words-short.txt\n,p\nQ\n",
    "ed-shell.ed": b"!echo hi\nh\nQ\n",
    "ed-wshell.ed": b"a\nx\n.\nw !cat\nh\nQ\n",
    "ed-modified.ed": b"a\nx\n.\nq\nh\nQ\n",
    "ed-eof.ed": b"a\nunsaved\n.\n",
    "ed-help.ed": b"h\nq\n",
}
MTIMES = {"older.txt": 1_000_000_000, "words.txt": 1_500_000_000}


def utils():
    for line in (ROOT / "userland/Makefile").read_text().splitlines():
        if line.startswith("UTILS := "):
            return line.split()[2:]
    sys.exit("check-userland: no UTILS in userland/Makefile")


def lib_table(side):
    objs = sorted((OUT / "obj" / side / "libutf").glob("*.o")) + sorted((OUT / "obj" / side / "libutil").glob("*.o"))
    return ud.members(objs)


def probe_rows():
    rows = {}
    for line in (ROOT / "userland/DEMAND.tsv").read_text().splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        rows.setdefault(f[0], set()).add(f[1])
    return rows


def tree_files(work):
    return {str(p.relative_to(work)): p.read_bytes() for p in sorted(work.rglob("*")) if p.is_file()}


def run_case(cid, util, stdin, args):
    work = OUT / "cases" / cid
    if work.exists():
        shutil.rmtree(work)
    (work / "dir").mkdir(parents=True)
    for name, data in FIXTURES.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_bytes(data)
    for name, t in MTIMES.items():
        os.utime(work / name, (t, t))
    binary = OUT / "linux" / util
    data = FIXTURES[stdin] if stdin != "-" else b""
    # argv[0] is /bin/<util>, the platform's form (controller ruling D-21:
    # absd-sh starts a bare name as /bin/<util>; compat-matrix.py and
    # cports-matrix.py run their Linux twins the same way).
    r = subprocess.run([f"/bin/{util}", *args], executable=str(binary), cwd=work, env={}, input=data,
                       capture_output=True, timeout=30)
    return format_result(r.returncode, r.stdout, r.stderr, tree_files(work), case_id=cid)


def tar_create_contents(data):
    """Only tar-create's bounded contents/hierarchy comparison, not metadata.

    The raw archive stays in the owning case evidence. Strict ustar headers,
    end records and regular/directory types are required before projection.
    This fixture helper establishes no general archive validation guarantee.
    """
    if len(data)>131072:raise ValueError("tar-create fixture exceeds bound")
    rows=[];end=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for member in archive:
            if len(rows)>=16:raise ValueError("tar-create too many fixture members")
            header=data[member.offset:member.offset+512]
            if header[257:265]!=b'ustar\x0000':raise ValueError("not native ustar")
            if member.offset != end:raise ValueError("noncontiguous native records")
            if header[156:157] not in (b'0',b'\x00',b'5'):raise ValueError("extension/non-native header")
            if member.offset_data != member.offset+512:raise ValueError("hidden extension header")
            if member.isfile():
                content=archive.extractfile(member).read()
                rows.append([member.name,'file',content.hex()])
            elif member.isdir():rows.append([member.name.rstrip('/'),'directory'])
            else:raise ValueError("unsupported tar-create member type")
            end=member.offset_data+((member.size+511)//512)*512
    if len(data)<end+1024 or any(data[end:]):raise ValueError("missing/nonzero end records")
    return (json.dumps(rows,separators=(',',':'))+'\n').encode()


def format_result(status, stdout, stderr, after, case_id=None):
    """A case's pin bytes: status, stdout, stderr and, when the case
    created, changed or removed a file of its directory (`after`: every
    file below it, relative name -> bytes), the "--- files" section.
    Also the guest runner's (scripts/userland-matrix.py) formatting."""
    if case_id == "tar-create" and "made.ustar" in after:
        after = dict(after)
        after["made.ustar"] = tar_create_contents(after["made.ustar"])
    out = (b"status %d\n--- stdout\n" % status) + stdout + b"--- stderr\n" + stderr
    # Files the case created, changed or removed in its directory (none for
    # most cases, whose pins then end at stderr): a written file, or a
    # scratch file left behind, shows here.
    changed = sorted(n for n in set(after) | set(FIXTURES) if after.get(n) != FIXTURES.get(n))
    if changed:
        out += b"--- files\n"
        for n in changed:
            if n not in after:
                out += b"removed %s\n" % n.encode()
            else:
                out += b"file %s %d\n" % (n.encode(), len(after[n])) + after[n]
    return out


def main():
    ports = utils()
    posix_a = ud.CPORTS / "lib" / "libabsd-posix.a"
    classify = ud.classifier(posix_a)
    probe = probe_rows()
    abs_lib, lin_lib = lib_table("absd"), lib_table("linux")
    (OUT / "demand").mkdir(exist_ok=True)
    gates = unresolved = 0
    failures = []
    for u in ports:
        elf = OUT / "absd" / u
        g = subprocess.run([sys.executable, "-I", ROOT / "scripts/check-c-elf.py", elf, "--map", f"{elf}.map"],
                           capture_output=True, text=True)
        print(g.stdout.strip().replace(str(OUT) + "/", ""))
        if g.returncode == 0:
            gates += 1
        else:
            failures.append(f"{u}: gate")
        need, pulled = ud.closure([OUT / "obj/absd" / f"{u}.o"], {} if u in {"diff", "hexdump"} else abs_lib)
        lneed, _ = ud.closure([OUT / "obj/linux" / f"{u}.o"], {} if u in {"diff", "hexdump"} else lin_lib)
        lines, bad, runtime_refusals, counts = [], [], [], {}
        for name in sorted(need):
            b, links, note = classify(name)
            counts[b] = counts.get(b, 0) + 1
            lines.append(f"{name}\t{b}\t{'yes' if links else 'no'}\t{note}")
            if not links or b == "MISSING":
                bad.append(name)
            elif b == "REFUSED":
                runtime_refusals.append(name)
        unresolved += len(bad)
        if bad:
            failures.append(f"{u}: unresolved {' '.join(bad)}")
        vs_probe_add = sorted(need - probe.get(u, set()))
        vs_probe_drop = sorted(probe.get(u, set()) - need)
        only_absd = sorted(need - lneed)
        only_linux = sorted(lneed - need)
        report = [f"# {u}: ABSD demand (bucket, links, note); members pulled: "
                  + " ".join(sorted(Path(p).parent.name + "/" + Path(p).name for p in pulled))]
        report += lines
        if u not in probe:
            report.append("# no historical unpatched probe for this utility; direct compiled demand above is authoritative")
        report.append(f"# against userland/DEMAND.tsv (unpatched probe): +{' +'.join(vs_probe_add) or ''} -{' -'.join(vs_probe_drop) or ''}")
        report.append(f"# only in the ABSD demand: {' '.join(only_absd)}")
        report.append(f"# only in the REFERENCE (gcc, glibc) demand: {' '.join(only_linux)}")
        (OUT / "demand" / f"{u}.txt").write_text("\n".join(report) + "\n")
        print(f"DEMAND {u} names={len(need)} " + " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
              + f" unresolved={len(bad)} runtime_refusals={','.join(runtime_refusals) or '-'}"
              + f" vs_probe=+{len(vs_probe_add)}/-{len(vs_probe_drop)} vs_reference=+{len(only_absd)}/-{len(only_linux)}")
    exp_dir = ROOT / "userland" / "expected"
    cases = 0
    seen = set()
    for line in (ROOT / "userland/cases.tsv").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        f = line.split("\t")
        if len(f) != 4:
            sys.exit(f"check-userland: bad case row: {line!r}")
        cid, util, stdin, args = f
        if util not in ports:
            sys.exit(f"check-userland: {cid}: {util} is not a port")
        seen.add(cid)
        got = run_case(cid, util, stdin, shlex.split(args))
        pin = exp_dir / cid
        if UPDATE:
            pin.write_bytes(got)
        elif not pin.exists() or pin.read_bytes() != got:
            failures.append(f"case {cid}: differs from userland/expected/{cid}")
            sys.stdout.write(f"CASE {cid} DIFFERS\n" + got.decode(errors="replace"))
        cases += 1
    stale = sorted(p.name for p in exp_dir.iterdir() if p.name not in seen)
    if stale:
        failures.append("pins without a case: " + " ".join(stale))
    div = ROOT / "userland/divergences.tsv"
    for line in div.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.split("\t")[0] not in seen:
            failures.append(f"divergences.tsv names no case: {line.split(chr(9))[0]}")
    if failures:
        print("check-userland: " + "; ".join(failures), file=sys.stderr)
        sys.exit(1)
    print(f"USERLAND BUILD OK ports={len(ports)} reproducible=2 gate={gates} unresolved={unresolved} "
          f"host_cases={cases} guest=unverified")


if __name__ == "__main__":
    main()
