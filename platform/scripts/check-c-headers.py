#!/usr/bin/env python3
"""The C header is a binding of the Rust runtime's C ABI, not a copy of it.

Checks c/include/absd/runtime.h against runtime/src/*.rs:
- every `__absd_std_*` prototype the header declares must be a
  `#[unsafe(no_mangle)] pub [unsafe] extern "C" fn` in runtime/src with the
  same name, arity, parameter types and return type under the fixed type
  map below (the header must not declare a hook twice), and every such
  Rust hook must be declared in the header;
- every ABSD_FS_* constant must equal the bit `__absd_std_fs_open`
  (storage.rs) tests for that flag (`read: flags & 1 != 0`, ...), and the
  bit the file server's open (fsd/src/server.rs) tests, since the runtime
  forwards the raw flags to it;
- the V1 `struct absd_raw_attr` and separate V2 `struct absd_raw_attr_v2`
  must list RawAttr/RawAttrV2 fields in order with the mapped types.
Exits 0 printing `C HEADERS OK hooks=<n> constants=<m>`, else 1 with
`C HEADERS MISMATCH <name>: ...` for the first mismatch.

Usage: check-c-headers.py ROOT [--header FILE]
       check-c-headers.py ROOT --self-test
--header checks another copy of the header against ROOT's Rust sources.
--self-test injects a parameter-type change, a return-type change, a
constant change, both versioned struct-field changes, a V2 hook layout
change and a removed prototype into scratch
copies and requires each to be refused by name.
"""
import os, pathlib, re, subprocess, sys, tempfile

SCALARS = {"usize": "size_t", "isize": "ptrdiff_t", "u64": "uint64_t", "i64": "int64_t",
           "u32": "uint32_t", "i32": "int32_t", "u8": "unsigned char",
           "RawAttr": "struct absd_raw_attr", "RawAttrV2": "struct absd_raw_attr_v2", "RawSpawn": "struct absd_raw_spawn"}
FLAGS = [("ABSD_FS_READ", "read"), ("ABSD_FS_WRITE", "write"), ("ABSD_FS_CREATE", "create"),
         ("ABSD_FS_CREATE_NEW", "create_new"), ("ABSD_FS_TRUNCATE", "truncate")]


def mismatch(name, why):
    print(f"C HEADERS MISMATCH {name}: {why}")
    sys.exit(1)


def norm(t):
    """One spelling per C type: no space around * ( ) [ ], single spaces elsewhere."""
    t = re.sub(r"\s+", " ", t).strip()
    return re.sub(r"\s*([*()\[\]])\s*", r"\1", t)


def c_of_rust(t):
    """The C spelling of a Rust FFI type, or None when the map has no entry."""
    t = t.strip()
    if t == "()": return "void"
    if t == "!": return "_Noreturn void"
    m = re.fullmatch(r"\*(mut|const)\s+(.+)", t)
    if m:
        const = "const " if m.group(1) == "const" else ""
        inner = m.group(2).strip()
        arr = re.fullmatch(r"\[\s*(\w+)\s*;\s*(\d+)\s*\]", inner)
        if arr:                                    # pointer to array: T (*)[N]
            elem = SCALARS.get(arr.group(1))
            return elem and f"{const}{elem} (*)[{arr.group(2)}]"
        elem = SCALARS.get(inner)
        return elem and f"{const}{elem} *"
    return SCALARS.get(t)


def rust_hooks(root):
    rust = "\n".join(p.read_text() for p in sorted((root / "runtime" / "src").glob("*.rs")))
    out = {}
    pat = re.compile(r'#\[unsafe\(no_mangle\)\]\s*pub (?:unsafe )?extern "C" fn (__absd_std_\w+)\s*'
                     r'\(([^)]*)\)\s*(?:->\s*([^{]+?))?\s*\{')
    for m in pat.finditer(rust):
        name, params, ret = m.group(1), m.group(2), (m.group(3) or "()")
        types = [p.split(":", 1)[1].strip() for p in params.split(",") if p.strip()]
        mapped = [c_of_rust(t) for t in types]
        for t, c in zip(types + [ret], mapped + [c_of_rust(ret)]):
            if c is None: mismatch(name, f"Rust type `{t}` has no entry in the type map")
        out[name] = ([norm(c) for c in mapped], norm(c_of_rust(ret)))
    return out


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def param_type(p, hook):
    """Drop the parameter name: `T *name` -> `T *`, `T (*name)[N]` -> `T (*)[N]`."""
    p = p.strip()
    m = re.fullmatch(r"(.+?)\(\s*\*\s*\w+\s*\)\s*(\[\d+\])", p)
    if m: return norm(f"{m.group(1)} (*){m.group(2)}")
    m = re.fullmatch(r"(.+?[\s*])(\w+)", p)
    if not m or not m.group(1).strip(): mismatch(hook, f"cannot read parameter `{p}` (every parameter is named)")
    return norm(m.group(1))


def c_hooks(header):
    out = {}
    code = re.sub(r"^\s*#.*$", " ", strip_comments(header), flags=re.M)   # no preprocessor lines
    for stmt in code.split(";"):
        if "__absd_std_" not in stmt: continue
        stmt = re.sub(r"\s+", " ", stmt).strip()
        stmt = stmt[stmt.rfind("}") + 1:].strip() if "}" in stmt else stmt
        m = re.fullmatch(r"(.+?)\(\s*\*\s*(__absd_std_\w+)\s*\((.*)\)\s*\)\s*(\[\d+\])", stmt)
        if m:                                       # T (*name(params))[N]: returns T (*)[N]
            ret, name, params = f"{m.group(1)} (*){m.group(4)}", m.group(2), m.group(3)
        else:
            m = re.fullmatch(r"(.+?)\b(__absd_std_\w+)\s*\((.*)\)", stmt)
            if not m: mismatch("header", f"cannot read declaration `{stmt}`")
            ret, name, params = m.group(1), m.group(2), m.group(3)
        if name in out: mismatch(name, "declared twice in the header")
        types = [] if params.strip() in ("", "void") else [param_type(p, name) for p in params.split(",")]
        out[name] = (types, norm(ret))
    return out


def check(root, header_path):
    header = header_path.read_text()
    rs, c = rust_hooks(root), c_hooks(header)
    if not c: mismatch("header", f"no __absd_std_* prototypes in {header_path}")
    for name, (ctypes, cret) in c.items():
        if name not in rs: mismatch(name, 'not a #[unsafe(no_mangle)] extern "C" fn in runtime/src')
        rtypes, rret = rs[name]
        if len(rtypes) != len(ctypes):
            mismatch(name, f"arity: rust {len(rtypes)} parameters, header {len(ctypes)}")
        for i, (r, h) in enumerate(zip(rtypes, ctypes)):
            if r != h: mismatch(name, f"parameter {i + 1}: rust maps to `{r}`, header has `{h}`")
        if rret != cret: mismatch(name, f"return: rust maps to `{rret}`, header has `{cret}`")
    for name in sorted(set(rs) - set(c)):
        mismatch(name, "exported by runtime/src but not declared in the header")

    storage = (root / "runtime" / "src" / "storage.rs").read_text()
    opener = re.search(r'fn __absd_std_fs_open\b.*?\n\}', storage, re.S)
    server = (root / "fsd" / "src" / "server.rs").read_text()
    served = re.search(r'fn open\(&mut self, channel: usize, flags: u32.*?\n    \}', server, re.S)
    if not opener: mismatch("ABSD_FS_*", "__absd_std_fs_open not found in storage.rs")
    if not served: mismatch("ABSD_FS_*", "the file server's open not found in fsd/src/server.rs")
    consts = 0
    for cname, field in FLAGS:
        cm = re.search(rf"^\s*#define {cname}\s+(\d+)u?\b", header, re.M)
        if not cm: mismatch(cname, "not defined in the header")
        for where, body in (("storage.rs", opener.group(0)), ("fsd/src/server.rs", served.group(0))):
            rm = re.search(rf"\b{field}:\s*flags\s*&\s*(\d+)\s*!=\s*0", body)
            if not rm: mismatch(cname, f"`{field}: flags & N != 0` not found in the open of {where}")
            if int(cm.group(1)) != int(rm.group(1)):
                mismatch(cname, f"header {cm.group(1)}, {where} tests {rm.group(1)}")
        consts += 1

    for rust_name, c_name in (("RawAttr", "absd_raw_attr"), ("RawAttrV2", "absd_raw_attr_v2")):
        rattr = re.search(r"pub struct " + rust_name + r"\s*\{([^}]*)\}", storage)
        cattr = re.search(r"struct " + c_name + r"\s*\{([^}]*)\}", strip_comments(header))
        if not rattr or not cattr: mismatch("struct " + c_name, "struct not found in storage.rs or the header")
        rfields = [(f.split(":")[0].split()[-1], norm(c_of_rust(f.split(":")[1]) or "?"))
                   for f in rattr.group(1).split(",") if ":" in f]
        cfields = [(d.split()[-1], norm(" ".join(d.split()[:-1]))) for d in cattr.group(1).split(";") if d.strip()]
        if rfields != cfields: mismatch("struct " + c_name, f"rust {rfields}, header {cfields}")
    return len(c), consts


def self_test(root):
    original = (root / "c" / "include" / "absd" / "runtime.h").read_text()
    cases = [
        ("parameter type", "uint32_t flags);", "int32_t flags);", "__absd_std_fs_open"),
        ("return type", "uint64_t __absd_std_ticks(void);", "int64_t __absd_std_ticks(void);", "__absd_std_ticks"),
        ("constant", "#define ABSD_FS_TRUNCATE   32u", "#define ABSD_FS_TRUNCATE   64u", "ABSD_FS_TRUNCATE"),
        ("V1 struct field", "    uint64_t links;\n};", "    uint32_t links;\n};", "struct absd_raw_attr"),
        ("V2 struct field", "    uint64_t mtime;", "    uint32_t mtime;", "struct absd_raw_attr_v2"),
        ("V2 hook layout", "uint64_t handle, struct absd_raw_attr_v2 *out);", "uint64_t handle, struct absd_raw_attr *out);", "__absd_std_fs_fstat_v2"),
        ("missing prototype", "uint64_t __absd_std_ticks(void);\n", "", "__absd_std_ticks"),
    ]
    with tempfile.TemporaryDirectory(prefix="check-c-headers.") as tmp:
        for label, old, new, name in cases:
            if original.count(old) != 1: print(f"C HEADERS SELF-TEST BROKEN: `{old}` not unique"); sys.exit(1)
            scratch = pathlib.Path(tmp) / "runtime.h"
            scratch.write_text(original.replace(old, new))
            run = subprocess.run([sys.executable, "-I", __file__, str(root), "--header", str(scratch)],
                                 capture_output=True, text=True)
            line = run.stdout.strip()
            print(f"injected {label}: exit {run.returncode}: {line}")
            if run.returncode != 1 or not line.startswith(f"C HEADERS MISMATCH {name}:"):
                print(f"C HEADERS SELF-TEST FAILED: {label} change was not refused by name"); sys.exit(1)
    print(f"C HEADERS SELF-TEST OK cases={len(cases)}")


def main():
    args = sys.argv[1:]
    if not args: print(__doc__, file=sys.stderr); sys.exit(2)
    root = pathlib.Path(args[0]).resolve()
    if args[1:] == ["--self-test"]: self_test(root); return
    header = root / "c" / "include" / "absd" / "runtime.h"
    if len(args) == 3 and args[1] == "--header": header = pathlib.Path(args[2])
    elif len(args) != 1: print(__doc__, file=sys.stderr); sys.exit(2)
    hooks, consts = check(root, header)
    print(f"C HEADERS OK hooks={hooks} constants={consts}")


main()
