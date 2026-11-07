#!/usr/bin/env python3
"""Per-member provenance of the Picolibc code the base userland ports link.

    scripts/picolibc-provenance.py --tarball T --build B --userland U

T is the pinned picolibc tarball (c/picolibc/PIN), B the Meson build
directory scripts/build-picolibc.sh left (its libc.a must be the pinned one;
its Ninja dependency log and compile_commands.json name what each object was
compiled from), U a userland build directory whose absd/NAME ELFs are the
gated bytes userland/PORTS.tsv records, with their objects (obj/absd) and the
toolchain record of each link; the kit (--kit) and POSIX adapter (--posix)
they were linked with default to U's siblings. Each port is relinked from
those inputs: the relinked ELF must be the gated ELF byte for byte, and the
members it retains are read from that link's own map.

Writes c/picolibc/PROVENANCE.tsv: one row per (libc.a member some port
links, file its compilation touched), with the Debian-format COPYING.picolibc
label of that file, the licence c/picolibc/LICENCE-LABELS.tsv maps that
label to, and its use:

  consumed  the compiler's include trace (-H) names the file and the line
            markers enter it: its text went into the object;
  probe     the dependency output names the file (for example a
            __has_include_next test) but the preprocessor never entered it.
            Recorded, never treated as source. A command that suppresses
            markers, or a marker stream that disagrees with the trace, is
            refused rather than read as a probe.

and c/picolibc/PROVENANCE.receipt.json, which binds the table to what it was
generated from: the table's own sha256, its members and their row counts,
and the sha256 of every repository file the generation depends on (the pins,
the port table, the label map, this script). scripts/provenance.py checks
the receipt on every run; provenance/config.toml pins the receipt's sha256.

An absolute host dependency that was only probed is recorded with its path
and observed bytes' hash, use=probe and empty label/licence: no source or
licence assertion is made for it. A consumed host input still needs its
exact reviewed path and hash in the label map.

Refuses: an input that does not match its pin; a relink that does not
reproduce the gated ELF; a kit libc.a that is not the pinned one stripped;
a build object whose bytes differ from the
pinned libc.a member; a source file in the build that differs from the
tarball; a stale dependency record; a consumed host file other than a reviewed clang
resource header (exact path and sha256 in the label map); a label with no
reviewed mapping or a label text that differs from the one reviewed. It
preprocesses (clang -E) but compiles nothing and writes nothing in B.
Python standard library and the recorded compiler only; no network.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("provenance", ROOT / "scripts/provenance.py")
pv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pv)
dep5, label, header, no_header_note = pv.dep5, pv.dep5_label, pv.source_header, pv.no_header_note
TABLE = "c/picolibc/PROVENANCE.tsv"
RECEIPT = "c/picolibc/PROVENANCE.receipt.json"
LABELS = "c/picolibc/LICENCE-LABELS.tsv"
BOUND = ["c/picolibc/PIN", "userland/PORTS.tsv", LABELS, "scripts/picolibc-provenance.py"]


class Refused(Exception):
    pass


def die(message):
    sys.exit(f"picolibc-provenance: {message}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pin(name, column):
    for line in (ROOT / "c/picolibc/PIN").read_text().splitlines():
        f = line.split("\t")
        if f[0] == name:
            return f[column]
    die(f"c/picolibc/PIN has no {name} row")


# The acknowledgements the accepted texts require in a distribution's
# documentation (owner decision 2026-10-29), by the label that requires each.
ACKNOWLEDGEMENTS = {
    "Other-16": "This product includes software developed at Cygnus Support, Inc.",
    "UCB-1": "This product includes software developed by the University of California, Berkeley.",
    "UCB-2": "This product includes software developed by the University of California, Berkeley and its contributors",
}
NOTICE = "c/picolibc/NOTICES.txt"
# Owner interpretations (2026-10-29): the label whose terms the notice states
# from LICENSES/<SPDX>.txt, after the label's own text.
INTERPRETATIONS = {"FreeBSD-1": "BSD-2-Clause"}


def notice_text(tarball_sha, sections, paragraphs, labels):
    """The distribution notice for the linked members: per licence text, the
    text as COPYING.picolibc writes it and each linked input's own header
    (its copyright and licence notice), verbatim; the acknowledgements."""
    out = [f"Picolibc 1.8.12 (tarball sha256 {tarball_sha}): notices for the libc.a members linked into the",
           "ABSD userland ports. Generated by scripts/picolibc-provenance.py from the pinned tarball; regenerate it,",
           "do not edit it. Naming an organisation acknowledges its work; it does not imply that it endorses ABSD.",
           "The upstream notices below are quoted, not this file's own licence statements.",
           "REUSE-" + "IgnoreStart", "", "== ACKNOWLEDGEMENTS"]
    out += [ACKNOWLEDGEMENTS[l] for l in sorted(ACKNOWLEDGEMENTS) if l in sections]
    for name in sorted(sections):
        out += ["", f"== LABEL {name}", paragraphs[name]]
        if name in INTERPRETATIONS:
            out += ["", f"-- TERMS {INTERPRETATIONS[name]} (owner interpretation of this text, 2026-10-29)",
                    (ROOT / f"LICENSES/{INTERPRETATIONS[name]}.txt").read_text().strip("\n")]
        for path, head, fallback in sorted(sections[name]):
            out += ["", f"-- FILE {path}"]
            out += [head] if head else [no_header_note(fallback)]
    out += ["", "REUSE-" + "IgnoreEnd"]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- probe or consumed

LINE_MARKER = re.compile(r'^# (\d+) "((?:[^"\\]|\\.)*)"((?: \d)*)$', re.M)
TRACE = re.compile(r"^\.+ (.+)$", re.M)
# Options that suppress or rewrite line markers or the include trace: a
# recorded command carrying one cannot classify a dependency.
UNMARKED = re.compile(r"^(-P|-C|-CC|-fpreprocessed|-fdirectives-only|-Wp,.*|-Xpreprocessor|-dM|-M|-MM|-H)$")


def consumed_files(preprocessed, trace, directory, main):
    """The files whose text entered a translation unit, made absolute against
    DIRECTORY: the main file and every header the compiler's include trace
    (-H) names. The line-marker stream must agree: it starts in the main
    file and has an entering marker (flag 1) for every traced header. A
    marker without flag 1 (a #line directive's logical name) proves
    nothing. Anything inconsistent is refused, never read as a probe."""
    norm = lambda p: os.path.normpath(os.path.join(directory, p.encode().decode("unicode_escape")))
    markers = [(norm(m.group(2)), m.group(3).split()) for m in LINE_MARKER.finditer(preprocessed)
               if not (m.group(2).startswith("<") and m.group(2).endswith(">"))]
    main = os.path.normpath(os.path.join(directory, main))
    if not markers or markers[0][0] != main:
        raise Refused(f"{main}: the preprocessed unit carries no line marker for its main file")
    entered = {name for name, flags in markers if "1" in flags}
    traced = {norm(p) for p in TRACE.findall(trace)}
    missing = sorted(traced - entered)
    if missing:
        raise Refused(f"{main}: the include trace names {missing[0]} but the marker stream never enters it")
    return {main} | traced


def preprocess_command(command):
    """The recorded compile command, turned into preprocessing to stdout with
    the include trace on stderr: no object, no dependency file, nothing
    written. A command whose options suppress line markers is refused."""
    args, out, skip = shlex.split(command), [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("-MQ", "-MF", "-MT", "-o"):
            skip = True
            continue
        if a in ("-MD", "-MMD", "-c"):
            continue
        if UNMARKED.match(a):
            raise Refused(f"the recorded command carries {a}, which suppresses or rewrites line markers")
        out.append(a)
    return out + ["-E", "-H", "-o", "-"]


def classify(deps, consumed, directory):
    """Classify recorded dependencies; refuse a trace the record omits.

    The real include trace is consumption evidence. The dependency record
    must contain it, and may additionally name files only probed.
    """
    recorded = {os.path.normpath(os.path.join(directory, dep)) for dep in deps}
    missing = sorted(consumed - recorded)
    if missing:
        raise Refused(f"{missing[0]}: consumed input absent from the dependency record")
    rows = []
    for dep in deps:
        path = os.path.normpath(os.path.join(directory, dep))
        rows.append((dep, "consumed" if path in consumed else "probe"))
    return rows


def host_input(dep, use, reviewed):
    """A host row's identity and terms, without licensing unconsumed probes."""
    if use not in ("probe", "consumed"):
        raise Refused(f"{dep}: unclassified host input")
    where = f"host:{dep}"
    digest = sha256(Path(dep).read_bytes())
    if use == "probe":
        return where, "", "", digest
    mapped = reviewed.get(where)
    if mapped is None or mapped[0] != digest:
        raise Refused(f"{dep}: consumed host file without a reviewed identity in {LABELS}")
    return where, where, mapped[1], digest


def port_link(name, upstream, elf, gated, userland, kit, posix, out_dir):
    """(libc.a members the port's ELF retains, members loaded but not
    retained, sha256 of the relink's map). The gated ELF must be the bytes
    userland/PORTS.tsv records, and relinking the port's recorded inputs must
    reproduce it byte for byte: only then does the relink's own map describe
    that ELF. Anything else is refused."""
    if sha256((userland / elf).read_bytes()) != gated:
        raise Refused(f"{userland / elf} is not the gated ELF userland/PORTS.tsv records")
    elf_bytes, text, trace = relink(name, upstream, userland / "obj/absd", kit, posix,
                                    (userland / f"{elf}.toolchain").read_text(), out_dir)
    if sha256(elf_bytes) != gated:
        raise Refused(f"{name}: relinking its recorded inputs does not reproduce the gated ELF")
    retained = set(re.findall(r"/libc\.a\(([^)]+)\)", text))
    if re.search(r"/libm\.a\(|libclang_rt", text):
        raise Refused(f"{name}: its link retains libm.a or clang builtins members: extend this record first")
    return retained, set(re.findall(r"/libc\.a\(([^)]+)\)", trace)) - retained, sha256(text.encode())


def relink(port, upstream, obj_dir, kit, posix, toolchain, out_dir):
    """Re-run a port's absd-cc link (userland/Makefile; c/bin/absd-cc) with
    the recorded inputs, writing a map and a trace. Returns (elf bytes, map
    text, trace text)."""
    tools = dict(line.split(" ", 1) for line in toolchain.splitlines() if " " in line)
    builtins, builtins_sha = tools["builtins"].rsplit(" ", 1)
    if sha256(Path(builtins).read_bytes()) != builtins_sha:
        raise Refused(f"{port}: the clang builtins archive differs from the one its link recorded")
    linker = tools["ld.lld"].split(" ", 1)[0]
    objs = [obj_dir / f"{port}.o"] + ([] if upstream.startswith("toybox-") else [obj_dir / "libutil.a", obj_dir / "libutf.a"])
    out = out_dir / port
    cmd = [linker, "-static", "-no-pie", "--gc-sections", "-T", str(kit / "absd-c.ld"), f"-Map={out}.map", "--trace",
           "-o", str(out), str(kit / "lib/crt0.o"), *map(str, objs), str(posix), "--start-group",
           str(kit / "lib/libabs.a"), str(kit / "lib/libc.a"), str(kit / "lib/libm.a"),
           str(kit / "lib/libabs_builtins.a"), builtins, "--end-group"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise Refused(f"{port}: relink failed: {r.stderr.strip()[:200]}")
    return out.read_bytes(), Path(f"{out}.map").read_text(), r.stdout


# ---------------------------------------------------------------- binding helpers

def elf_sections(data):
    """{name: (address, size)} of an ELF64 file's allocated sections."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise Refused("not an ELF64 file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = headers[shstrndx]
    names = data[strtab[4]:strtab[4] + strtab[5]]
    out = {}
    for name, _, flags, addr, _, size, *_ in headers:
        if flags & 2 and size:  # SHF_ALLOC
            out[names[name:names.index(b"\0", name)].decode()] = (addr, size)
    return out


def map_sections(text):
    """{name: (address, size)} of the output sections an ld.lld map lists."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) == 5 and f[4].startswith(".") and re.fullmatch(r"[0-9a-f]+", f[0]) and re.fullmatch(r"[0-9a-f]+", f[2]):
            if int(f[0], 16) and int(f[2], 16):  # loaded sections; .symtab and the like sit at 0
                out[f[4]] = (int(f[0], 16), int(f[2], 16))
    return out


def ar_members(data):
    """{name: [bytes, ...]} of a System V / GNU ar archive."""
    if data[:8] != b"!<arch>\n":
        raise Refused("not an ar archive")
    pos, longnames, out = 8, b"", {}
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name, size = header[:16].decode().strip(), int(header[48:58].decode().strip())
        body = data[pos + 60:pos + 60 + size]
        if name == "//":
            longnames = body
        elif name not in ("/", "/SYM64/"):
            if name.startswith("/") and name[1:].isdigit():
                start = int(name[1:])
                name = longnames[start:longnames.index(b"/\n", start)].decode()
            out.setdefault(name.rstrip("/"), []).append(body)
        pos += 60 + size + (size & 1)
    return out


def receipt_for(rows, linked, extra):
    table = "\n".join(["\t".join(("member", "linked_by", "input", "label", "licence", "use", "sha256"))]
                      + ["\t".join(r) for r in rows]) + "\n"
    coverage = {}
    for r in rows:
        coverage[r[0]] = coverage.get(r[0], 0) + 1
    receipt = {
        "schema": "absd-member-table-receipt/1",
        "table": TABLE,
        "table_sha256": sha256(table.encode()),
        "rows": len(rows),
        "consumed_rows": sum(1 for r in rows if r[5] == "consumed"),
        "probe_rows": sum(1 for r in rows if r[5] == "probe"),
        "member_count": len(linked),
        "members": sorted(linked),
        "coverage": dict(sorted(coverage.items())),
        "bound_files": {p: sha256((ROOT / p).read_bytes()) for p in BOUND},
        **extra,
    }
    return table, json.dumps(receipt, indent=1, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tarball", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--userland", required=True)
    parser.add_argument("--kit", help="the C kit the ports were linked with (default: beside U, ckit-build/kit)")
    parser.add_argument("--posix", help="the POSIX adapter archive (default: beside U, cports-build/lib/libabsd-posix.a)")
    args = parser.parse_args()
    tarball, build, userland = Path(args.tarball), Path(args.build).resolve(), Path(args.userland)
    kit = Path(args.kit) if args.kit else userland.parent / "ckit-build/kit"
    posix = Path(args.posix) if args.posix else userland.parent / "cports-build/lib/libabsd-posix.a"
    try:
        run(tarball, build, userland, kit, posix)
    except Refused as error:
        die(str(error))


def run(tarball, build, userland, kit, posix):
    data = tarball.read_bytes()
    if sha256(data) != pin("picolibc", 2):
        raise Refused(f"{tarball} is not the pinned picolibc tarball")
    libc = (build / "libc.a").read_bytes()
    if sha256(libc) != pin("picolibc-libc.a", 2):
        raise Refused(f"{build}/libc.a is not the pinned libc.a")
    archive = tarfile.open(tarball)
    members = {m.name.split("/", 1)[1]: m for m in archive.getmembers() if m.isfile()}
    source = lambda rel: archive.extractfile(members[rel]).read()
    paragraphs = {}
    files, texts = dep5(source("COPYING.picolibc").decode(), paragraphs)
    sections = {}
    in_archive = ar_members(libc)

    reviewed = {}
    for line in (ROOT / LABELS).read_text().splitlines():
        if line and not line.startswith("#"):
            name, text_sha, licence, basis = line.split("\t")
            reviewed[name] = (text_sha, licence, basis)

    # The kit's libc.a must be the pinned archive, debug-stripped as
    # scripts/build-c-kit.sh makes it.
    with tempfile.TemporaryDirectory() as tmp:
        stripped = Path(tmp) / "libc.a"
        subprocess.run(["llvm-strip-18", "--strip-debug", "-o", str(stripped), str(build / "libc.a")], check=True)
        if stripped.read_bytes() != (kit / "lib/libc.a").read_bytes():
            raise Refused(f"{kit}/lib/libc.a is not the pinned libc.a, debug-stripped")

        # Which members each shipped port links: from the port's own link,
        # re-run with its recorded inputs (port_link). A recorded map is
        # never read.
        linked, ports, maps, loaded = {}, {}, {}, {}
        for line in (ROOT / "userland/PORTS.tsv").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            name, upstream, _, elf, gated = line.split("\t")[:5]
            retained, unretained, map_sha = port_link(name, upstream, elf, gated, userland, kit, posix, Path(tmp))
            ports[name], maps[name], loaded[name] = gated, map_sha, sorted(unretained)
            for member in retained:
                linked.setdefault(member, set()).add(name)

    query = subprocess.run(["ninja", "-t", "query", "libc.a"], cwd=build, capture_output=True, text=True, check=True).stdout
    objects = [l.strip() for l in query.split("outputs:")[0].splitlines()[2:] if l.strip()]
    deps, current = {}, None
    for line in subprocess.run(["ninja", "-t", "deps"], cwd=build, capture_output=True, text=True, check=True).stdout.splitlines():
        if line and not line.startswith(" "):
            current = line.split(":")[0]
            deps[current] = []
            if "(VALID)" not in line:
                raise Refused(f"{current}: the dependency record is not valid ({line.strip()})")
        elif line.strip():
            deps[current].append(line.strip())
    commands = {e["output"]: e for e in json.loads((build / "compile_commands.json").read_text())}
    by_name = {}
    for o in objects:
        by_name.setdefault(os.path.basename(o), []).append(o)

    rows = []
    for member in sorted(linked):
        if len(by_name.get(member, [])) != 1 or len(in_archive.get(member, [])) != 1:
            raise Refused(f"libc.a member {member} is not exactly one object of the build and of the archive")
        obj = by_name[member][0]
        if (build / obj).read_bytes() != in_archive[member][0]:
            raise Refused(f"{obj} differs from the pinned libc.a's member {member}")
        if obj not in deps or obj not in commands:
            raise Refused(f"{obj}: no dependency record or compile command")
        entry = commands[obj]
        pre = subprocess.run(preprocess_command(entry["command"]), cwd=entry["directory"],
                             capture_output=True, text=True)
        if pre.returncode:
            raise Refused(f"{obj}: preprocessing failed: {pre.stderr.strip()[:200]}")
        consumed = consumed_files(pre.stdout, pre.stderr, entry["directory"], entry["file"])
        for dep, use in classify(deps[obj], consumed, entry["directory"]):
            if dep.startswith("../src/"):
                rel = os.path.normpath(dep[len("../src/"):])
                if rel not in members:
                    raise Refused(f"{rel} is not in the pinned tarball")
                if (build / dep).read_bytes() != source(rel):
                    raise Refused(f"{rel}: the build's source differs from the pinned tarball's")
                name, digest, where = label(files, rel), sha256(source(rel)), rel
                if use == "consumed":
                    sections.setdefault(name, set()).add(
                        (rel, header(source(rel).decode("utf-8", "replace")), label(files, rel, True)[1]))
            elif os.path.isabs(dep):
                where, name, licence, digest = host_input(dep, use, reviewed)
                rows.append((member, ",".join(sorted(linked[member])), where, name, licence, use, digest))
                continue
            else:
                rel = dep + ".in" if dep + ".in" in members else None
                if rel is None:
                    raise Refused(f"generated input {dep} has no template in the tarball")
                where, name, digest = f"build:{dep}", label(files, rel), sha256((build / dep).read_bytes())
            mapped = reviewed.get(name)
            if mapped is None:
                raise Refused(f"{where}: label {name} has no reviewed mapping in {LABELS}")
            if name in texts and sha256(texts[name].encode()) != mapped[0]:
                raise Refused(f"label {name}: its COPYING.picolibc text differs from the one reviewed")
            rows.append((member, ",".join(sorted(linked[member])), where, name, mapped[1], use, digest))
    notice = notice_text(sha256(data), sections, paragraphs, reviewed)
    table, receipt = receipt_for(rows, linked, {
        "source_sha256": sha256(data),
        "notice": NOTICE, "notice_sha256": sha256(notice.encode()),
        "notice_sections": {k: sorted(p for p, _, _ in v) for k, v in sorted(sections.items())},
        "inputs": {"picolibc_tarball_sha256": sha256(data), "libc_a_sha256": sha256(libc),
                   "port_elf_sha256": dict(sorted(ports.items())), "relinked_map_sha256": dict(sorted(maps.items())),
                   "loaded_but_not_retained": {k: v for k, v in sorted(loaded.items()) if v}}})
    (ROOT / TABLE).write_text(table)
    (ROOT / NOTICE).write_text(notice)
    (ROOT / RECEIPT).write_text(receipt)
    print(f"picolibc-provenance: {len(linked)} linked member(s), {len(rows)} input row(s) "
          f"({sum(1 for r in rows if r[5] == 'probe')} probe), receipt sha256 {sha256(receipt.encode())}")


if __name__ == "__main__":
    main()
