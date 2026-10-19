#!/usr/bin/env python3
"""The filesystem has exactly two object kinds: File (1) and Dir (2).

SPEC A13: the C kit's O_NOFOLLOW no-op (and the POSIX adapter's lstat == stat,
readlink EINVAL) is honest only while no link kind exists. This holds the
invariant at every place a kind is defined or encoded:
- fs/src/lib.rs        `enum Kind` lists exactly File and Dir;
- fs/src/image.rs      the image encoder maps File->1, Dir->2, and the
                       decoder accepts exactly 1 and 2 (anything else refused);
- fsd/src/server.rs    the wire attr encoder (attr_bytes) maps File->1, Dir->2;
- runtime/src/storage.rs  the RawAttr fill maps File->1, Dir->2;
- scripts/absd_fs.py   the host image reader accepts kinds (1, 2) only.
The Rust side is also held by the exhaustive match in fs/src/tests.rs
(object_kinds_are_exactly_file_and_dir), which stops compiling on a new
variant.

SPEC A21 (R12): a file server kind word outside 1..=2 is refused at every
consumer, never read as a file or a directory. The consumer sites:
- runtime/src/wire_kind.rs  the one runtime decoder: 1 File, 2 Dir, else -5;
- runtime/src/fsd.rs   `kind` is that decoder, and every `kind(&attr)` use
                       in runtime/src propagates its refusal with `?`;
- runtime/src/storage.rs  stat_kind maps the decoded kind exhaustively;
                       remote_attr (the std/C stat and fstat hooks) refuses
                       before writing; write_attr never copies the wire kind;
- runtime/src/wire_kind.rs entry_word + storage.rs readdir hook: a listing
                       entry of unknown kind is MARKED unknown (0), never
                       converted and never failing the listing; entry_word
                       is used by the readdir hook's entry_attr only;
- patches/rust-1.95.0-absd-std.patch  std's FileAttr conversion is fallible
                       (1 file, 2 directory, else the -5 error), so
                       metadata, symlink_metadata and File::metadata never
                       report an unknown kind as a file; a read_dir entry of
                       unknown kind keeps no attributes: its file_type() is
                       the -5 error and its metadata() is stat of its path.
Exits 0 printing `FS KINDS OK kinds=2 sites=<n>`, else 1 with
`FS KINDS MISMATCH <site>: ...` for the first mismatch.

Usage: check-fs-kinds.py ROOT
       check-fs-kinds.py ROOT --self-test
       check-fs-kinds.py ROOT --exercise
--self-test copies the sites into scratch trees, adds a third kind (or
undoes a refusal) at each one in turn, and requires each copy to be
refused by name.
--exercise compiles and runs, on the host with rustc +1.95.0, the runtime
decoder's test (tests/runtime_wire_kind.rs: kinds 0 and 3 in a server
attribute record are -5 for one object and marked 0 for a listing entry)
and std's FileAttr conversion and DirEntry extracted from the patch
(tests/std_fs_kind.rs: kinds 0 and 3 are an io::Error, never a file; an
unknown entry's file_type() is that error and its metadata() is stat),
printing `FS KINDS EXERCISE OK`.
"""
import os, pathlib, re, shutil, subprocess, sys, tempfile

EXPECTED = {"File": 1, "Dir": 2}


class Mismatch(Exception):
    pass


def block(text, anchor, site):
    """The body of the brace block opened on the first line matching anchor."""
    m = re.search(anchor, text)
    if not m:
        raise Mismatch(f"{site}: anchor {anchor!r} not found")
    start = text.index("{", m.start())
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], text.count("\n", 0, m.start()) + 1
    raise Mismatch(f"{site}: unbalanced block after {anchor!r}")


def arms(body):
    return [a.strip() for a in re.findall(r"^\s*([^\n]*?=>[^\n]*?),?\s*$", body, re.M)]


def check_enum(root, site):
    body, line = block((root / "fs/src/lib.rs").read_text(), r"pub enum Kind\s*\{", site)
    variants = [v.strip() for v in body.split(",") if v.strip()]
    if variants != list(EXPECTED):
        raise Mismatch(f"{site} (line {line}): variants {variants}, want {list(EXPECTED)}")


def check_encoder(path, anchor):
    def run(root, site):
        body, line = block((root / path).read_text(), anchor, site)
        got = {}
        for arm in arms(body):
            m = re.fullmatch(r"Kind::(\w+)\s*=>\s*(\d+),?", arm)
            if not m:
                raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
            got[m.group(1)] = int(m.group(2))
        if got != EXPECTED:
            raise Mismatch(f"{site} (line {line}): encodes {got}, want {EXPECTED}")
    return run


def check_decoder(root, site):
    body, line = block((root / "fs/src/image.rs").read_text(), r"let kind = match bytes\[offset \+ 24\]", site)
    got, refuses = {}, False
    for arm in arms(body):
        m = re.fullmatch(r"(\d+)\s*=>\s*Kind::(\w+),?", arm)
        if m:
            got[m.group(2)] = int(m.group(1))
        elif re.fullmatch(r"_\s*=>\s*return Err\(.*\),?", arm):
            refuses = True
        else:
            raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
    if got != EXPECTED or not refuses:
        raise Mismatch(f"{site} (line {line}): decodes {got} refuse-others={refuses}, want {EXPECTED} and a refusal")


def check_python(root, site):
    text = (root / "scripts/absd_fs.py").read_text()
    found = re.findall(r"\bkind not in \(([^)]*)\)", text)
    if len(found) != 1:
        raise Mismatch(f"{site}: want exactly one `kind not in (...)` test, found {len(found)}")
    values = sorted(int(v) for v in found[0].split(",") if v.strip())
    if values != sorted(EXPECTED.values()):
        raise Mismatch(f"{site}: accepts kinds {values}, want {sorted(EXPECTED.values())}")
    if not re.search(r'"dir":\s*kind == 2\b', text):
        raise Mismatch(f"{site}: directory test is not `kind == 2`")


def check_wire_decoder(root, site):
    text = (root / "runtime/src/wire_kind.rs").read_text()
    body, line = block(text, r"pub\(crate\) enum WireKind\s*\{", site)
    variants = [v.strip() for v in body.split(",") if v.strip()]
    if variants != list(EXPECTED):
        raise Mismatch(f"{site} (line {line}): variants {variants}, want {list(EXPECTED)}")
    if not re.search(r"pub\(crate\) const UNKNOWN_KIND: i64 = -5;", text):
        raise Mismatch(f"{site}: UNKNOWN_KIND is not -5 (EIO)")
    body, line = block(text, r"pub\(crate\) fn decode\(word: u32\)", site)
    got, refuses = {}, False
    for arm in arms(body):
        m = re.fullmatch(r"(\d+)\s*=>\s*Ok\(WireKind::(\w+)\),?", arm)
        if m:
            got[m.group(2)] = int(m.group(1))
        elif re.fullmatch(r"_\s*=>\s*Err\(UNKNOWN_KIND\),?", arm):
            refuses = True
        else:
            raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
    if got != EXPECTED or not refuses:
        raise Mismatch(f"{site} (line {line}): decodes {got} refuse-others={refuses}, want {EXPECTED} and a refusal")


def check_entry_word(root, site):
    text = (root / "runtime/src/wire_kind.rs").read_text()
    if not re.search(r"^pub\(crate\) const ENTRY_UNKNOWN: u32 = 0;$", text, re.M):
        raise Mismatch(f"{site}: ENTRY_UNKNOWN is not 0 (neither file nor directory)")
    body, line = block(text, r"pub\(crate\) fn word\(kind: WireKind\)", site)
    got = {}
    for arm in arms(body):
        m = re.fullmatch(r"WireKind::(\w+)\s*=>\s*(\d+),?", arm)
        if not m:
            raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
        got[m.group(1)] = int(m.group(2))
    if got != EXPECTED:
        raise Mismatch(f"{site} (line {line}): word encodes {got}, want {EXPECTED}")
    body, line = block(text, r"pub\(crate\) fn entry_word\(", site)
    if sorted(arms(body)) != sorted(["Ok(kind) => word(kind)", "Err(_) => ENTRY_UNKNOWN"]):
        raise Mismatch(f"{site} (line {line}): entry_word does not mark an unknown kind ENTRY_UNKNOWN: {arms(body)}")


def check_fsd_kind(root, site):
    text = (root / "runtime/src/fsd.rs").read_text()
    if not re.search(r"pub\(crate\) fn kind\(attr: &\[u8; proto::ATTR_BYTES\]\) -> Result<WireKind, i64>", text):
        raise Mismatch(f"{site}: fsd::kind does not return Result<WireKind, i64>")
    body, line = block(text, r"pub\(crate\) fn kind\(", site)
    if body.strip() != "crate::wire_kind::of_attr(attr)":
        raise Mismatch(f"{site} (line {line}): fsd::kind is not the wire_kind decoder: {body.strip()!r}")


def check_kind_consumers(root, site):
    for path in sorted((root / "runtime/src").glob("*.rs")):
        text = path.read_text()
        for m in re.finditer(r"\bkind\(&attr\)", text):
            if not text.startswith("?", m.end()):
                line = text.count("\n", 0, m.start()) + 1
                raise Mismatch(f"{site}: {path.name}:{line} uses kind(&attr) without propagating its refusal")


def check_stat_kind(root, site):
    body, line = block((root / "runtime/src/storage.rs").read_text(), r"pub\(crate\) fn stat_kind\(", site)
    if "crate::fsd::kind(&attr)?" not in body:
        raise Mismatch(f"{site} (line {line}): does not decode with crate::fsd::kind(&attr)?")
    if re.search(r"\belse\b|[=!]=", body):
        raise Mismatch(f"{site} (line {line}): compares kinds instead of matching the decoded kind")
    got = {}
    for arm in arms(body):
        m = re.fullmatch(r"WireKind::(\w+)\s*=>\s*Kind::(\w+),?", arm)
        if not m or m.group(1) != m.group(2):
            raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
        got[m.group(1)] = True
    if sorted(got) != sorted(EXPECTED):
        raise Mismatch(f"{site} (line {line}): maps {sorted(got)}, want {sorted(EXPECTED)}")


def check_remote_attr(root, site):
    text = (root / "runtime/src/storage.rs").read_text()
    for name, args in (("stat", "path, length, out"), ("fstat", "handle, out")):
        for suffix in ("", "_v2"):
            hook = "__absd_std_fs_" + name + suffix
            exported, _ = block(text, r'pub unsafe extern "C" fn ' + hook + r'\(', site)
            if exported.strip() != "unsafe { " + name + "(" + args + ") }":
                raise Mismatch(f"{site}: {hook} does not use the common metadata route")
    body, line = block(text, r"fn remote_attr<T: From<RawAttrV2>>\(", site)
    if not re.search(r"let kind = match crate::wire_kind::of_attr\(&bytes\) \{\s*Ok\(kind\) => crate::wire_kind::word\(kind\),"
                     r"\s*Err\(code\) => return code,\s*\};\s*write_attr\(&bytes, kind, out\);", body):
        raise Mismatch(f"{site} (line {line}): does not refuse an unknown kind before writing the record")


def check_write_attr(root, site):
    body, line = block((root / "runtime/src/storage.rs").read_text(), r"fn write_attr<T: From<RawAttrV2>>\(", site)
    if not re.search(r"^\s*kind,$", body, re.M) or "half(0)" in body:
        raise Mismatch(f"{site} (line {line}): the kind word is not the caller's decoding")


def check_readdir_hook(root, site):
    text = (root / "runtime/src/storage.rs").read_text()
    body, line = block(text, r"unsafe fn readdir<T: From<RawAttrV2>>\(", site)
    for hook in ("__absd_std_fs_readdir", "__absd_std_fs_readdir_v2"):
        exported, _ = block(text, r'pub unsafe extern "C" fn ' + hook + r'\(', site)
        if exported.strip() != "unsafe { readdir(path, length, index, name, capacity, out) }":
            raise Mismatch(f"{site}: {hook} does not delegate to the common readdir route")
    fsd, _ = block(body, r"if crate::fsd::active\(\)", site)
    if "entry_attr(&attr, out);" not in fsd or "remote_attr(" in fsd:
        raise Mismatch(f"{site} (line {line}): the file server entry is not marked through entry_attr")
    body, line = block(text, r"fn entry_attr<T: From<RawAttrV2>>\(", site)
    if body.strip() != "write_attr(bytes, crate::wire_kind::entry_word(bytes), out);":
        raise Mismatch(f"{site} (line {line}): entry_attr does not mark through wire_kind::entry_word: {body.strip()!r}")
    uses = [(path.name, len(re.findall(r"\bentry_word\(", path.read_text())))
            for path in sorted((root / "runtime/src").glob("*.rs")) if path.name != "wire_kind.rs"]
    if [u for u in uses if u[1]] != [("storage.rs", 1)]:
        raise Mismatch(f"{site}: entry_word must be used once, by entry_attr: {[u for u in uses if u[1]]}")


STD_PATCH = "patches/rust-1.95.0-absd-std.patch"


def std_fs_source(root, site):
    """The std patch's new library/std/src/sys/fs/absd.rs, without the '+'."""
    text = (root / STD_PATCH).read_text()
    m = re.search(r"^\+\+\+ b/library/std/src/sys/fs/absd\.rs\n@@ [^\n]*\n((?:\+[^\n]*\n)*)", text, re.M)
    if not m:
        raise Mismatch(f"{site}: the sys/fs/absd.rs section is missing")
    return "".join(l[1:] + "\n" for l in m.group(1).splitlines())


def check_std_conversion(root, site):
    text = std_fs_source(root, site)
    if not re.search(r"^const KIND_FILE: u32 = 1;$", text, re.M) or not re.search(r"^const KIND_DIR: u32 = 2;$", text, re.M):
        raise Mismatch(f"{site}: KIND_FILE/KIND_DIR are not 1/2")
    if re.search(r"impl From<RawAttr> for FileAttr|raw\.into\(\)|FileAttr::from\(", text):
        raise Mismatch(f"{site}: an infallible RawAttr -> FileAttr conversion remains")
    body, line = block(text, r"let directory = match raw\.kind", site)
    got, refuses = {}, False
    for arm in arms(body):
        m = re.fullmatch(r"KIND_(FILE|DIR)\s*=>\s*(true|false),?", arm)
        if m:
            got[m.group(1)] = m.group(2)
        elif re.fullmatch(r"_\s*=>\s*return Err\(error\(-5\)\),?", arm):
            refuses = True
        else:
            raise Mismatch(f"{site} (line {line}): unexpected arm {arm!r}")
    if got != {"FILE": "false", "DIR": "true"} or not refuses:
        raise Mismatch(f"{site} (line {line}): converts {got} refuse-others={refuses}, want FILE/DIR and a refusal")
    if not re.search(r"impl TryFrom<RawAttr> for FileAttr", text):
        raise Mismatch(f"{site}: no fallible TryFrom<RawAttr> for FileAttr")


def check_std_dir_entry(root, site):
    text = std_fs_source(root, site)
    body, line = block(text, r"(?m)^fn entry_attr\(raw: RawAttr\) -> Option<FileAttr>", site)
    if body.strip() != "FileAttr::try_from(raw).ok()":
        raise Mismatch(f"{site} (line {line}): entry_attr is not FileAttr::try_from(raw).ok(): {body.strip()!r}")
    if "entries.push((name, entry_attr(raw)));" not in text:
        raise Mismatch(f"{site}: readdir does not keep unknown entries through entry_attr")
    body, line = block(text, r"(?m)^pub struct DirEntry \{", site)
    if not re.search(r"^\s*attr: Option<FileAttr>,$", body, re.M):
        raise Mismatch(f"{site} (line {line}): DirEntry attr is not Option<FileAttr>")
    entry, line = block(text, r"(?m)^impl DirEntry \{", site)
    body, _ = block(entry, r"pub fn file_type\(&self\)", site)
    if sorted(arms(body)) != sorted(["Some(attr) => Ok(attr.file_type())", "None => Err(error(-5))"]):
        raise Mismatch(f"{site} (line {line}): file_type of an unknown entry is not the -5 error: {arms(body)}")
    body, _ = block(entry, r"pub fn metadata\(&self\)", site)
    if sorted(arms(body)) != sorted(["Some(attr) => Ok(attr.clone())", "None => stat(&self.path())"]):
        raise Mismatch(f"{site} (line {line}): metadata of an unknown entry is not stat of its path: {arms(body)}")


SITES = [
    ("fs/src/lib.rs:enum", check_enum),
    ("fs/src/image.rs:encode", check_encoder("fs/src/image.rs", r"bytes\.push\(match record\.kind")),
    ("fs/src/image.rs:decode", check_decoder),
    ("fsd/src/server.rs:attr_bytes", check_encoder("fsd/src/server.rs", r"fn attr_bytes[^{]*\{\s*frame\s*\.u32\(match attr\.kind")),
    ("runtime/src/storage.rs:fill", check_encoder("runtime/src/storage.rs", r"kind: match attr\.kind")),
    ("scripts/absd_fs.py:records", check_python),
    ("runtime/src/wire_kind.rs:decode", check_wire_decoder),
    ("runtime/src/fsd.rs:kind", check_fsd_kind),
    ("runtime/src:kind-consumers", check_kind_consumers),
    ("runtime/src/storage.rs:stat_kind", check_stat_kind),
    ("runtime/src/wire_kind.rs:entry_word", check_entry_word),
    ("runtime/src/storage.rs:remote_attr", check_remote_attr),
    ("runtime/src/storage.rs:write_attr", check_write_attr),
    ("runtime/src/storage.rs:readdir", check_readdir_hook),
    (STD_PATCH + ":FileAttr", check_std_conversion),
    (STD_PATCH + ":DirEntry", check_std_dir_entry),
]


def check(root):
    for site, run in SITES:
        run(root, site)
    return len(SITES)


# Each mutation adds a third kind at one site; (file, old, new, site expected in the refusal).
MUTATIONS = [
    ("fs/src/lib.rs", "    Dir,\n}", "    Dir,\n    Link,\n}", "fs/src/lib.rs:enum"),
    ("fs/src/image.rs", "            Kind::Dir => 2,\n        });", "            Kind::Dir => 2,\n            Kind::Link => 3,\n        });", "fs/src/image.rs:encode"),
    ("fs/src/image.rs", "                2 => Kind::Dir,\n", "                2 => Kind::Dir,\n                3 => Kind::Link,\n", "fs/src/image.rs:decode"),
    ("fsd/src/server.rs", "            Kind::Dir => 2,\n        })\n        .u32(u32::from(attr.readonly))", "            Kind::Dir => 2,\n            Kind::Link => 3,\n        })\n        .u32(u32::from(attr.readonly))", "fsd/src/server.rs:attr_bytes"),
    ("runtime/src/storage.rs", "            Kind::Dir => 2,\n        },\n        readonly", "            Kind::Dir => 2,\n            Kind::Link => 3,\n        },\n        readonly", "runtime/src/storage.rs:fill"),
    ("scripts/absd_fs.py", "kind not in (1, 2)", "kind not in (1, 2, 3)", "scripts/absd_fs.py:records"),
    # R12: each consumer site undone to classify an unknown kind
    ("runtime/src/wire_kind.rs", "        _ => Err(UNKNOWN_KIND),", "        _ => Ok(WireKind::File),", "runtime/src/wire_kind.rs:decode"),
    ("runtime/src/wire_kind.rs", "    Dir,\n}", "    Dir,\n    Link,\n}", "runtime/src/wire_kind.rs:decode"),
    ("runtime/src/fsd.rs", "    crate::wire_kind::of_attr(attr)\n", "    Ok(if attr[0] == 2 { WireKind::Dir } else { WireKind::File })\n", "runtime/src/fsd.rs:kind"),
    ("runtime/src/fsd.rs", "match kind(&attr)? {", "match kind(&attr).unwrap_or(WireKind::File) {", "runtime/src:kind-consumers"),
    ("runtime/src/storage.rs", "            Ok(match crate::fsd::kind(&attr)? {\n                WireKind::File => Kind::File,\n                WireKind::Dir => Kind::Dir,\n            })", "            Ok(if crate::fsd::kind(&attr)? == WireKind::Dir { Kind::Dir } else { Kind::File })", "runtime/src/storage.rs:stat_kind"),
    ("runtime/src/storage.rs", "                Err(code) => return code,\n            };\n            write_attr", "                Err(_) => 1,\n            };\n            write_attr", "runtime/src/storage.rs:remote_attr"),
    ("runtime/src/storage.rs", "        kind,\n        readonly: half(4),", "        kind: half(0),\n        readonly: half(4),", "runtime/src/storage.rs:write_attr"),
    ("runtime/src/storage.rs", "                entry_attr(&attr, out);\n", "                remote_attr(Ok(attr), out);\n", "runtime/src/storage.rs:readdir"),
    ("runtime/src/storage.rs", "write_attr(bytes, crate::wire_kind::entry_word(bytes), out);", "write_attr(bytes, 1, out);", "runtime/src/storage.rs:readdir"),
    ("runtime/src/wire_kind.rs", "        Err(_) => ENTRY_UNKNOWN,", "        Err(_) => 1,", "runtime/src/wire_kind.rs:entry_word"),
    ("runtime/src/wire_kind.rs", "pub(crate) const ENTRY_UNKNOWN: u32 = 0;", "pub(crate) const ENTRY_UNKNOWN: u32 = 1;", "runtime/src/wire_kind.rs:entry_word"),
    ("runtime/src/fsd.rs", "    crate::wire_kind::of_attr(attr)\n", "    Ok(crate::wire_kind::decode(crate::wire_kind::entry_word(attr)).unwrap_or(WireKind::File))\n", "runtime/src/fsd.rs:kind"),
    (STD_PATCH, "+            _ => return Err(error(-5)),", "+            _ => false,", STD_PATCH + ":FileAttr"),
    (STD_PATCH, "+    FileAttr::try_from(raw)\n+}", "+    Ok(FileAttr::from(raw))\n+}", STD_PATCH + ":FileAttr"),
    (STD_PATCH, "+            None => Err(error(-5)),", "+            None => Ok(FileType { directory: false }),", STD_PATCH + ":DirEntry"),
    (STD_PATCH, "+            None => stat(&self.path()),", "+            None => Ok(FileAttr { raw: RawAttrCopy { directory: false, readonly: false, size: 0, filesystem: 0, serial: 0, links: 0 } }),", STD_PATCH + ":DirEntry"),
    (STD_PATCH, "+        entries.push((name, entry_attr(raw)));", "+        entries.push((name, Some(FileAttr::try_from(raw)?)));", STD_PATCH + ":DirEntry"),
    (STD_PATCH, "+    FileAttr::try_from(raw).ok()\n", "+    Some(FileAttr::try_from(raw).unwrap_or_else(|_| unreachable!()))\n", STD_PATCH + ":DirEntry"),
]


def self_test(root):
    files = sorted({f for f, *_ in MUTATIONS})
    for path, old, new, site in MUTATIONS:
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            for f in files:
                (scratch / f).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / f, scratch / f)
            text = (scratch / path).read_text()
            if text.count(old) != 1:
                raise SystemExit(f"FS KINDS SELF-TEST BROKEN: mutation anchor for {site} not unique")
            (scratch / path).write_text(text.replace(old, new))
            out = subprocess.run([sys.executable, "-I", __file__, str(scratch)], capture_output=True, text=True)
            if out.returncode != 1 or f"FS KINDS MISMATCH {site}" not in out.stdout:
                raise SystemExit(f"FS KINDS SELF-TEST FAILED: third kind at {site} not refused: {out.stdout.strip()!r}")
            print(f"refused: {out.stdout.strip()}")
    print(f"FS KINDS SELF-TEST OK mutations={len(MUTATIONS)}")


# Items of std's sys/fs/absd.rs the conversion test needs, as anchors of
# brace blocks (with the attribute lines above them).
STD_ITEMS = [
    r"(?m)^struct RawAttr \{",
    r"(?m)^fn error\(result: i64\)",
    r"(?m)^pub struct FileAttr \{",
    r"(?m)^struct RawAttrCopy \{",
    r"(?m)^impl TryFrom<RawAttr> for FileAttr \{",
    r"(?m)^pub struct FileType \{",
    r"(?m)^impl FileType \{",
    r"(?m)^fn entry_attr\(raw: RawAttr\)",
    r"(?m)^pub struct DirEntry \{",
    r"(?m)^impl DirEntry \{",
]


def std_items(root):
    text = std_fs_source(root, STD_PATCH + ":FileAttr")
    lines = text.splitlines()
    out = [l for l in lines if re.fullmatch(r"const KIND_(FILE|DIR): u32 = \d+;", l)]
    for anchor in STD_ITEMS:
        m = re.search(anchor, text, re.M)
        if not m:
            raise SystemExit(f"FS KINDS EXERCISE BROKEN: {anchor!r} not in the std patch")
        first = text.count("\n", 0, m.start())
        while first > 0 and (lines[first - 1].startswith("#[") or lines[first - 1].startswith("///")):
            first -= 1
        body, _ = block(text, anchor, "std")
        start = sum(len(l) + 1 for l in lines[:first])
        out.append(text[start:text.index(body, m.start()) + len(body)] + "}")
    file_type, _ = block(text, r"pub fn file_type\(&self\) -> FileType", "std")
    out.append("impl FileAttr {\n    pub fn file_type(&self) -> FileType {" + file_type + "}\n}")
    return "\n\n".join(out) + "\n"


def exercise(root):
    out = root / ".host-target/fs-kinds"
    out.mkdir(parents=True, exist_ok=True)
    items = out / "std_fs_items.rs"
    items.write_text(std_items(root))
    env = {k: v for k, v in os.environ.items() if k != "RUSTFLAGS"}
    env["ABSD_STD_FS_ITEMS"] = str(items)
    for name in ("runtime_wire_kind", "std_fs_kind"):
        subprocess.run(["rustc", "+1.95.0", "--edition", "2024", "--target", "x86_64-unknown-linux-gnu",
                        "--test", str(root / "tests" / f"{name}.rs"), "-o", str(out / name)],
                       env=env, check=True)
        run = subprocess.run([str(out / name)], capture_output=True, text=True)
        result = [l for l in run.stdout.splitlines() if l.startswith("test result:")]
        print(f"{name}: {result[-1] if result else run.stdout.strip()!r}")
        if run.returncode != 0:
            print(run.stdout + run.stderr)
            raise SystemExit(f"FS KINDS EXERCISE FAILED: {name}")
    print("FS KINDS EXERCISE OK")


def main():
    args = sys.argv[1:]
    if not args or len(args) > 2 or (len(args) == 2 and args[1] not in ("--self-test", "--exercise")):
        raise SystemExit(__doc__.split("Usage:")[1].strip())
    root = pathlib.Path(args[0]).resolve()
    if len(args) == 2 and args[1] == "--exercise":
        exercise(root)
        return
    if len(args) == 2:
        self_test(root)
        return
    try:
        sites = check(root)
    except Mismatch as e:
        print(f"FS KINDS MISMATCH {e}")
        sys.exit(1)
    print(f"FS KINDS OK kinds={len(EXPECTED)} sites={sites}")


if __name__ == "__main__":
    main()
