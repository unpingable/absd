#!/usr/bin/env python3
"""Demand probe of the base userland (userland/README.md, "Demand").

This historical discovery probe remains sbase-specific; it does not emit
Toybox DEMAND rows. scripts/check-userland.py computes direct object demand
for the admitted standalone Toybox adaptations during the actual build.

For every utility of the staged sbase tree (scripts/stage-userland.sh) this
compiles the utility with the kit's absd-cc under sbase's own CPPFLAGS
(plus the one build adaptation ADAPT below),
computes its demand the way docs/c-ecosystem-20261010/posix/DEMAND.md does
(the names the utility's object and the libutil/libutf members it pulls
reference and do not define), trial-links it through absd-cc with sbase's
libutil.a and libutf.a (compiled by absd-cc) and the POSIX adapter
(libabsd-posix.a, as the cports Makefile links; Picolibc's strerror hook
is the kit's since R13, c/libabs/strerror_hook.c), runs
the kit's ELF gate (check-c-elf.py --map) on a successful link, and
classifies every demanded name, plus every name the trial link reports
undefined behind a Picolibc object, in one bucket:

  PICOLIBC  defined by Picolibc 1.8.12 (libc.a, libm.a) and by nothing earlier
            on the link line
  KIT       the kit's own (libabs.a, libabs_builtins.a, clang's builtins), or
            KIT-FIVE in cports/demand/classify.tsv
  ADAPTER   defined by libabsd-posix.a (or ADAPTER in classify.tsv)
  REFUSED   refused by contract: REFUSED in classify.tsv (the adapter's
            explicit run-time refusals), or a facility docs/C-INTERFACE.md
            section 10 says is not provided (spawn, wait, signals beyond the
            adapter's, mmap, dup/pipe, termios, select/poll, sockets): a name
            no archive defines, so the link refuses it
  MISSING   no archive defines it and no contract refuses it (a kit gap)

classify.tsv's bucket wins where it names the symbol (KIT-FIVE is KIT here,
KIT-GAP and UNKNOWN are MISSING); otherwise the first archive on absd-cc's
link line that defines the name decides (the adapter, then libabs.a, then
Picolibc, then the builtins). The `links` column says whether any archive
defines the name. A utility is portable when it compiles, links and passes
the ELF gate; it then needs no adapter change. A REFUSED name that resolves
is a run-time refusal (stated in the note); one that does not resolve blocks
the link and needs a declared per-port patch (userland/patches/) or
port-local refusal glue.

Writes userland/DEMAND.tsv (utility, symbol, bucket, links, via, note) and
userland/DEMAND-SUMMARY.tsv (one row per utility) and prints
`USERLAND DEMAND OK utilities=N portable=M`. Builds go to
$ABSD_USERLAND_BUILD/demand (default <campaign>/userland-build/demand); the
staged tree is read in place and never written.
"""
import os, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAMP = ROOT.parent
KIT = Path(os.environ.get("ABSD_CKIT_BUILD", CAMP / "ckit-build")) / "kit"
CPORTS = Path(os.environ.get("ABSD_CPORTS_BUILD", CAMP / "cports-build"))
UP = Path(os.environ.get("ABSD_USERLAND_UPSTREAM", CAMP / "upstream"))
BUILD = Path(os.environ.get("ABSD_USERLAND_BUILD", CAMP / "userland-build")) / "demand"
CLANG = os.environ.get("ABSD_CLANG", "clang-18")
# sbase's Makefile CPPFLAGS, verbatim.
CPPFLAGS = ["-D_DEFAULT_SOURCE", "-D_NETBSD_SOURCE", "-D_BSD_SOURCE", "-D_XOPEN_SOURCE=700",
            "-D_FILE_OFFSET_BITS=64"]
# One build adaptation, on every compile (userland/README.md "Build
# adaptations"): userland/include goes first on the include path. It holds
# only regex.h, a wrapper that defines size_t before the kit's <regex.h>:
# Picolibc 1.8.12's declares regex_t with size_t but includes <stddef.h>
# under __need_ptrdiff_t only (regex.h:41-49), so sbase grep.c and sed.c,
# which include <regex.h> first, do not compile without it.
ADAPT = [f"-I{ROOT / 'userland' / 'include'}"]
# Lane plan (scout-userland.md 7) and the image's inventory (scripts/operator_image.py).
T2 = ["printf", "test", "grep", "sort", "sed", "od", "cmp"]
T3 = ["ed", "find"]
T6 = ["tar"]
NATIVE = ["echo", "pwd", "ls", "cat", "printenv", "uname", "mkdir", "rm", "mv", "cp", "head", "tail",
          "wc", "sha256sum", "date", "sync"]
UUTILS = ["basename", "seq", "cut", "fold", "nl", "uniq"]
# Deliberately absent from /bin (scripts/cmds-matrix.py ABSENT): never ported.
DO_NOT_PORT = ["kill", "chmod", "chown", "touch", "ln"]
# docs/C-INTERFACE.md section 10: not provided by the kit or the adapter.
CONTRACT_REFUSED = {
    "fork": "spawn: not provided (C-INTERFACE 10)", "vfork": "spawn: not provided (C-INTERFACE 10)",
    "execv": "exec*: not provided (C-INTERFACE 10)", "execve": "exec*: not provided (C-INTERFACE 10)",
    "execvp": "exec*: not provided (C-INTERFACE 10)", "execl": "exec*: not provided (C-INTERFACE 10)",
    "execlp": "exec*: not provided (C-INTERFACE 10)", "execle": "exec*: not provided (C-INTERFACE 10)",
    "posix_spawn": "spawn: not provided (C-INTERFACE 10)", "posix_spawnp": "spawn: not provided (C-INTERFACE 10)",
    "wait": "wait*: not provided (C-INTERFACE 10)", "waitpid": "wait*: not provided (C-INTERFACE 10)",
    "wait3": "wait*: not provided (C-INTERFACE 10)", "wait4": "wait*: not provided (C-INTERFACE 10)",
    "sigaction": "signals: not provided (C-INTERFACE 10)", "alarm": "signals: not provided (C-INTERFACE 10)",
    "sigemptyset": "signals: not provided (C-INTERFACE 10)", "sigaddset": "signals: not provided (C-INTERFACE 10)",
    "sigfillset": "signals: not provided (C-INTERFACE 10)", "sigsuspend": "signals: not provided (C-INTERFACE 10)",
    "sigprocmask": "signals: -1/ENOSYS where the kit answers it (C-INTERFACE 10)",
    "mmap": "not provided (C-INTERFACE 10)", "munmap": "not provided (C-INTERFACE 10)",
    "dup": "not provided (C-INTERFACE 10, CPA-036)", "dup2": "not provided (C-INTERFACE 10, CPA-036)",
    "pipe": "not provided (C-INTERFACE 10, CPA-036)",
    "tcgetattr": "termios: not provided (C-INTERFACE 10)", "tcsetattr": "termios: not provided (C-INTERFACE 10)",
    "select": "not provided (C-INTERFACE 10)", "poll": "not provided (C-INTERFACE 10)",
    "socket": "sockets: not provided (C-INTERFACE 10)", "connect": "sockets: not provided (C-INTERFACE 10)",
    "bind": "sockets: not provided (C-INTERFACE 10)", "sendto": "sockets: not provided (C-INTERFACE 10)",
    "recvfrom": "sockets: not provided (C-INTERFACE 10)", "getaddrinfo": "sockets: not provided (C-INTERFACE 10)",
    "freeaddrinfo": "sockets: not provided (C-INTERFACE 10)", "gai_strerror": "sockets: not provided (C-INTERFACE 10)",
    "setsockopt": "sockets: not provided (C-INTERFACE 10)",
}


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def nm(args, objs):
    out = run(["llvm-nm-18", *args, *objs]).stdout
    return out


def defined_in(archives):
    names = set()
    for line in nm(["--defined-only", "--extern-only"], archives).splitlines():
        parts = line.split()
        if len(parts) == 3:
            names.add(parts[2])
    return names


def members(archive_objs):
    """{object path: (defined set, undefined set)} for loose objects."""
    table = {}
    for obj in archive_objs:
        d, u = set(), set()
        for line in nm([], [obj]).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] not in "Uvw":
                if parts[1].isupper():
                    d.add(parts[2])
            elif len(parts) == 2 and parts[0] in ("U", "w", "v"):
                u.add(parts[1])
        table[obj] = (d, u)
    return table


def closure(objs, libtable):
    """The names `objs` and the archive members they pull (lazy archive
    semantics over libtable, {member: (defined, undefined)}) reference and do
    not define, and the members pulled."""
    d0, u0 = set(), set()
    for d, u in members(objs).values():
        d0 |= d
        u0 |= u
    pulled, need, have = [], u0 - d0, set(d0)
    changed = True
    while changed:
        changed = False
        for m, (d, uu) in libtable.items():
            if m not in pulled and d & need:
                pulled.append(m)
                have |= d
                need = (need | uu) - have
                changed = True
    return need, pulled


def classifier(posix_a):
    """A function name -> (bucket, links, note), over the kit at KIT and the
    adapter archive given."""
    # Resolvers, in absd-cc's link order after the program's own inputs.
    builtins = Path(run([CLANG, "-print-resource-dir"]).stdout.strip()) / "lib/linux/libclang_rt.builtins-x86_64.a"
    adapter = defined_in([posix_a])
    kit = defined_in([KIT / "lib/libabs.a"])
    pico = defined_in([KIT / "lib/libc.a", KIT / "lib/libm.a"])
    kitb = defined_in([KIT / "lib/libabs_builtins.a", builtins])
    classify = {}
    for line in (ROOT / "cports/demand/classify.tsv").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        f = line.split("\t")
        classify[f[0]] = (f[1], f[2] if len(f) > 2 else "")
    bucket_map = {"KIT-FIVE": "KIT", "KIT-GAP": "MISSING", "UNKNOWN": "MISSING"}

    def classify_name(name):
        links = name in adapter or name in kit or name in pico or name in kitb
        if name in classify:
            b, note = classify[name]
            b = bucket_map.get(b, b)
            if links or b not in ("ADAPTER", "KIT"):
                if b == "REFUSED" and not links:
                    note += " [no archive defines it: refused at link time]"
                return b, links, note
            # classify.tsv names an owner that defines nothing today (the
            # stage-2 rows for names reached only through Picolibc's popen).
            if name in CONTRACT_REFUSED:
                return "REFUSED", links, f"{CONTRACT_REFUSED[name]}; classify.tsv {b}: {note}"
            return "MISSING", links, f"classify.tsv {b} but no archive defines it: {note}"
        if name in CONTRACT_REFUSED:
            return "REFUSED", links, CONTRACT_REFUSED[name] + ("" if links else " [refused at link time]")
        if name in adapter:
            return "ADAPTER", links, ""
        if name in kit:
            return "KIT", links, ""
        if name in pico:
            return "PICOLIBC", links, ""
        if name in kitb:
            return "KIT", links, "builtins"
        return "MISSING", links, "no archive defines it"

    return classify_name


def main():
    staged = sorted(p for p in (UP / "sbase" / "src").glob("sbase-*") if p.is_dir())
    if len(staged) != 1:
        sys.exit("userland-demand: run scripts/stage-userland.sh first")
    src = staged[0]
    absd_cc = KIT / "bin" / "absd-cc"
    posix_a = CPORTS / "lib" / "libabsd-posix.a"
    for need in (absd_cc, posix_a):
        if not need.exists():
            sys.exit(f"userland-demand: {need} missing (scripts/build-c-kit.sh, scripts/build-posix.sh)")
    if BUILD.exists():
        shutil.rmtree(BUILD)
    (BUILD / "lib").mkdir(parents=True)
    (BUILD / "bin").mkdir()
    prefix = [f"-ffile-prefix-map={UP}=/upstream", f"-ffile-prefix-map={ROOT}=/absd"]
    cflags = CPPFLAGS + ADAPT + prefix + [f"-I{src}"]
    # libutf and libutil, each member compiled by absd-cc; a member that does
    # not compile is recorded and left out of its archive.
    lib_fail = {}
    lib_objs = {}
    makefile = (src / "Makefile").read_text()
    for lib in ("libutf", "libutil"):
        block = re.search(rf"^{lib.upper()}OBJ =\\\n((?:\t.*\n)+)", makefile, re.M).group(1)
        names = [n.strip().rstrip("\\").strip() for n in block.splitlines()]
        objs = []
        for n in names:
            stem = Path(n).stem
            obj = BUILD / "lib" / f"{lib}-{stem}.o"
            r = run([absd_cc, "-c", *cflags, "-o", obj, src / lib / f"{stem}.c"])
            if r.returncode:
                lib_fail[f"{lib}/{stem}.c"] = first_error(r.stderr)
            else:
                objs.append(obj)
        lib_objs[lib] = objs
        r = run([os.environ.get("ABSD_AR", "llvm-ar-18"), "rcs", BUILD / "lib" / f"{lib}.a", *objs])
        if r.returncode:
            sys.exit(f"userland-demand: {lib}.a: {r.stderr}")
    libtable = members(lib_objs["libutf"] + lib_objs["libutil"])
    classify_name = classifier(posix_a)

    utils = re.search(r"^BIN =\\\n((?:\t.*\n)+)", makefile, re.M).group(1)
    utils = [u.strip().rstrip("\\").strip() for u in utils.splitlines()]
    rows, summary = [], []
    for u in utils:
        obj = BUILD / "bin" / f"{u}.o"
        r = run([absd_cc, "-c", *cflags, "-o", obj, src / f"{u}.c"])
        if r.returncode:
            summary.append([u, "no", "-", "-", 0, 0, 0, 0, 0, 0, disposition(u, False),
                            "compile: " + first_error(r.stderr)])
            continue
        need, pulled = closure([obj], libtable)
        demand = {n: "program" for n in sorted(need)}
        elf = BUILD / "bin" / u
        link = run([absd_cc, "-o", elf, obj, BUILD / "lib/libutil.a", BUILD / "lib/libutf.a", posix_a])
        linked = link.returncode == 0
        for m in re.finditer(r"undefined symbol: (\S+)\n((?:>>> .*\n)+)", link.stderr + "\n"):
            name, refs = m.group(1), m.group(2)
            if name not in demand:
                via = re.search(r"\((libc\.a|libm\.a)\(([^)]+)\)\)", refs)
                demand[name] = f"via Picolibc {via.group(2)}" if via else "via link"
        gate = "-"
        if linked:
            g = run([sys.executable, "-I", ROOT / "scripts/check-c-elf.py", elf, "--map", f"{elf}.map"])
            gate = "OK" if g.returncode == 0 else g.stdout.strip().split(": ", 1)[-1]
        counts = {b: 0 for b in ("PICOLIBC", "KIT", "ADAPTER", "REFUSED", "MISSING")}
        blockers = []
        for name, via in sorted(demand.items()):
            b, links, note = classify_name(name)
            counts[b] += 1
            rows.append([u, name, b, "yes" if links else "no", via, note])
            if not links:
                blockers.append(name)
        portable = linked and gate == "OK"
        why = "" if portable else ("unresolved: " + " ".join(blockers) if blockers else
                                   ("link: " + first_error(link.stderr) if not linked else "gate: " + gate))
        summary.append([u, "yes", "yes" if linked else "no", gate, len(demand)] + list(counts.values())
                       + [disposition(u, portable), why])
    head_rows = "# userland/DEMAND.tsv: written by scripts/userland-demand.py over sbase " + src.name.split("-", 1)[1] + \
        " (userland/PIN). One row per (utility, demanded name). Buckets as the script's docstring.\n" + \
        "# utility\tsymbol\tbucket\tlinks\tvia\tnote\n"
    (ROOT / "userland/DEMAND.tsv").write_text(head_rows + "".join("\t".join(map(str, r)) + "\n" for r in rows))
    head_sum = "# userland/DEMAND-SUMMARY.tsv: written by scripts/userland-demand.py. One row per sbase utility.\n" + \
        "# libutil/libutf members that did not compile under absd-cc: " + \
        (", ".join(f"{k} ({v})" for k, v in sorted(lib_fail.items())) or "none") + "\n" + \
        "# utility\tcompiles\tlinks\telf_gate\tnames\tPICOLIBC\tKIT\tADAPTER\tREFUSED\tMISSING\tdisposition\tblocker\n"
    (ROOT / "userland/DEMAND-SUMMARY.tsv").write_text(head_sum + "".join("\t".join(map(str, r)) + "\n" for r in summary))
    n_portable = sum(1 for s in summary if s[1] == "yes" and s[2] == "yes" and s[3] == "OK")
    for s in summary:
        print("DEMAND " + " ".join(map(str, s[:4])) + f" names={s[4]} " + s[10] + (f" [{s[11]}]" if s[11] else ""))
    for k, v in sorted(lib_fail.items()):
        print(f"DEMAND lib {k} does not compile: {v}")
    print(f"USERLAND DEMAND OK utilities={len(summary)} portable={n_portable}")


def first_error(text):
    for line in text.splitlines():
        if "error" in line:
            line = re.sub(r"^.*?/sbase-[^/]*/", "", line)
            return line.replace("\t", " ").strip()[:200]
    return (text.strip().splitlines() or ["?"])[0][:200]


def disposition(u, portable):
    if u in DO_NOT_PORT:
        return "do-not-port"
    if u in T2:
        return "T2"
    if u in T3:
        return "T3"
    if u in T6:
        return "T6"
    if u in NATIVE:
        return "native-present"
    if u in UUTILS:
        return "uutils-present"
    return "candidate" if portable else "not-planned"


if __name__ == "__main__":
    main()
