"""Render DEMAND.md's per-program and union tables from the collected demand files.

Usage: python3 -I tables.py DEMAND_DIR > tables.md
Reads <variant>.undef.txt, <variant>.residual.txt, picolibc-1.8.12-defined.txt and
classify.tsv from DEMAND_DIR. Symbols internal to Lua (luaD_*, lua_*) appear only
because ldo.c failed to compile in the lua-posix variant and are left out.
"""
import collections, os, sys

d = sys.argv[1]
BUCKETS = ["PICOLIBC", "KIT-FIVE", "ADAPTER", "REFUSED", "KIT-GAP", "UNKNOWN"]
PROGRAMS = [
    ("Lua 5.4.9 (generic configuration, recommended)", ["lua-generic"]),
    ("Lua 5.4.9 (posix configuration, not recommended)", ["lua-posix"]),
    ("zlib 1.3.2 with example and minigzip", ["zlib-example", "zlib-minigzip"]),
    ("SQLite 3.54.0 shell and speedtest1 (recommended configuration, no WAL)", ["sqlite-shell", "sqlite-speedtest1"]),
    ("SQLite 3.54.0 shell with WAL kept (comparison)", ["sqlite-shell-wal"]),
]

def lines(name):
    p = os.path.join(d, name)
    return [l.rstrip("\n") for l in open(p)] if os.path.exists(p) else []

pico = set(lines("picolibc-1.8.12-defined.txt"))
klass = {}
for l in lines("classify.tsv"):
    if not l or l.startswith("#"):
        continue
    s, b, note = (l.split("\t") + ["", ""])[:3]
    klass[s] = (b, note)

def bucket(s):
    if s in klass:
        return klass[s]
    return ("PICOLIBC", "") if s in pico else ("UNKNOWN", "not defined by Picolibc and not yet classified")

def internal(s):
    return s.startswith("luaD_") or s.startswith("lua_")

union = collections.OrderedDict()
out = []
for title, variants in PROGRAMS:
    direct, via = {}, {}
    for v in variants:
        for s in lines(f"{v}.undef.txt"):
            if not internal(s):
                direct[s] = v
        for l in lines(f"{v}.residual.txt"):
            s, ref = l.split("\t")
            if not internal(s) and s not in direct:
                via.setdefault(s, ref)
    if variants == ["lua-posix"]:
        for s in ("_setjmp", "_longjmp"):
            direct[s] = "lua-posix (ldo.c, failed to compile)"
    syms = sorted(set(direct) | set(via), key=str.lower)
    counts = collections.Counter(bucket(s)[0] for s in syms)
    out.append(f"### {title}\n")
    out.append("Variants: " + ", ".join(f"`{v}`" for v in variants) + ". Counts: " +
               ", ".join(f"{b} {counts[b]}" for b in BUCKETS) + f"; total {len(syms)}.\n")
    out.append("| Symbol | Bucket | Demand | Note |\n|---|---|---|---|")
    for s in syms:
        b, note = bucket(s)
        how = "program" if s in direct else f"via Picolibc `{via[s]}`"
        out.append(f"| `{s}` | {b} | {how} | {note} |")
        if not title.endswith("(comparison)") and "not recommended" not in title:
            union.setdefault(s, set()).add(title.split(" ")[0])
    out.append("")

counts = collections.Counter(bucket(s)[0] for s in union)
out.append("### Union of the recommended configurations\n")
out.append("| Bucket | Count | Symbols |\n|---|---|---|")
for b in BUCKETS:
    syms = sorted((s for s in union if bucket(s)[0] == b), key=str.lower)
    out.append(f"| {b} | {len(syms)} | " + " ".join(f"`{s}`" for s in syms) + " |")
out.append(f"| total | {len(union)} | |")
print("\n".join(out))
