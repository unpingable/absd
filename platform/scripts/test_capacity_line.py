#!/usr/bin/env python3
"""Capacity producer fields and historical/current consumer boundaries.

The consumer patterns are read out of the consumers' own source (never
copied here), so a change there is tested; u1-endurance.py is only read,
never imported or run.
"""
import ast, importlib.util, pathlib, re

here = pathlib.Path(__file__).resolve().parent


def source_pattern(path, name):
    """The module-level `name = re.compile(<literal>[, re.FLAGS])` in `path`."""
    found = []
    for node in ast.parse(path.read_text(), str(path)).body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name):
            continue
        call = node.value
        assert isinstance(call, ast.Call) and ast.unparse(call.func) == "re.compile", ast.unparse(call)
        flags = 0
        for arg in call.args[1:]:
            for part in ast.unparse(arg).split("|"):
                part = part.strip()
                assert re.fullmatch(r"re\.[A-Z]+", part), part
                flags |= getattr(re, part[3:])
        found.append(re.compile(ast.literal_eval(call.args[0]), flags))
    assert len(found) == 1, f"{path.name}: {len(found)} assignments of {name}"
    return found[0]


U1 = source_pattern(here / "u1-endurance.py", "CAPACITY")
SSH = source_pattern(here / "contain-matrix.py", "SSH_CAPACITY")
AGENT = source_pattern(here / "agent-exec.py", "CAPACITY")

spec = importlib.util.spec_from_file_location("contain_matrix", here / "contain-matrix.py")
contain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contain)
assert (SSH.pattern, SSH.flags) == (contain.SSH_CAPACITY.pattern, contain.SSH_CAPACITY.flags)

BOOT = "ab" * 16
HEAD = (f"SERVED CAPACITY boot={BOOT} accepted_reclaimed=4 slots=0 pool=0 net_sockets=4 net_closing=0 "
        "processes=3 handles=58 pipes=24 cells=1 frames=635")
LINE = HEAD + " heap_pages_peak=254 link=down\n"

record = contain.capacity_record(SSH, LINE)
assert record is not None and record["link"] == "down" and record["heap_pages_peak"] == 254, record
assert record["boot"] == BOOT, record
for word in ("up", "unknown"):
    assert contain.capacity_record(SSH, HEAD + f" heap_pages_peak=254 link={word}\r\n")["link"] == word
u1 = U1.search(LINE)
assert u1 is not None and u1.group(1) == BOOT and u1.group(12) == "254", u1
# agent-exec.py's pattern (end-anchored): the appended field parses, and a line
# without it (a tree before the field) still does.
for text in (LINE, HEAD + " heap_pages_peak=254\n"):
    m = AGENT.search(text)
    assert m is not None and m.group("boot") == BOOT and m.group("heap_pages_peak") == "254", text
assert AGENT.search(LINE).group("link") == "down"

# contain-matrix must refuse every malformed form (its wait loop then fails at the deadline).
BAD = {
    "no link": HEAD + " heap_pages_peak=254\n",
    "link not at end": HEAD + " link=down heap_pages_peak=254\n",
    "trailing token": HEAD + " heap_pages_peak=254 link=down extra=1\n",
    "malformed value": HEAD + " heap_pages_peak=254 link=bogus\n",
    "empty value": HEAD + " heap_pages_peak=254 link=\n",
    "double space": HEAD + " heap_pages_peak=254  link=down\n",
}
for what, text in BAD.items():
    assert contain.capacity_record(SSH, text) is None, what
    if what != "no link":
        assert AGENT.search(text) is None, f"agent-exec: {what}"
print("CAPACITY LINE CONSUMERS OK")

# A3 consumer preparation: old producers remain valid; only the new named
# numeric tail is added. Missing telemetry is unknown (None), never zero.
FSD = source_pattern(here / "contain-matrix.py", "FSD_CAPACITY")
LINK = source_pattern(here / "link-matrix.py", "CAPACITY")
U1_FSD = source_pattern(here / "u1-endurance.py", "FSD_CAPACITY")
frame_path = here.parent / "docs/c-ecosystem-20261010/qual/frame-retention/frame-retention.py"
FRAME = source_pattern(frame_path, "SERVED")
FRAME_FSD = source_pattern(frame_path, "FSD")
spec = importlib.util.spec_from_file_location("agent_exec_capacity", here / "agent-exec.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
assert (AGENT.pattern, AGENT.flags) == (agent.CAPACITY.pattern, agent.CAPACITY.flags)
assert LINK.search(LINE).group(10) == "down"
FSD_LINE = (f"FSD CAPACITY boot={BOOT} settled_releases=4 fs_objects=1 rotated_logs=0 "
            "bound=0 opens=0 draining=0 heap_pages_peak=254\n")
assert contain.capacity_record(SSH, LINE)["heap_free_pages"] is None
assert contain.capacity_record(FSD, FSD_LINE)["heap_free_pages"] is None
assert agent.capacity(LINE)["heap_free_pages"] is None
assert agent.capacity(HEAD + " heap_pages_peak=254\n")["heap_free_pages"] is None
for free in (0, 1, 100):
    for ending in ("\n", "\r\n"):
        for link in ("up", "down", "unknown"):
            new = HEAD + f" heap_pages_peak=254 link={link} heap_free_pages={free}" + ending
            fsd_new = FSD_LINE.rstrip("\n") + f" heap_free_pages={free}" + ending
            assert contain.capacity_record(SSH, new)["heap_free_pages"] == free
            assert contain.capacity_record(FSD, fsd_new)["heap_free_pages"] == free
            assert agent.capacity(new)["heap_free_pages"] == free
            # This metric is observation only, not an added equality/leak gate.
            assert agent.capacity_diff(agent.capacity(LINE), agent.capacity(new)) == []
            assert U1.search(new).group(12) == "254"
            assert U1_FSD.search(fsd_new).group(8) == "254"
            assert FRAME.search(new).group(6) == "254"
            assert FRAME_FSD.search(fsd_new).group(1) == "254"
            # link-matrix previously accepts LF only; preserve that policy.
            if ending == "\n":
                assert LINK.search(new).group(10) == link
            else:
                assert LINK.search(new) is None
for tail in ("", "-1", "word", "1.0", "1 heap_free_pages=2", "1 extra=2", "1 "):
    new = LINE.rstrip("\n") + " heap_free_pages=" + tail + "\n"
    fsd_new = FSD_LINE.rstrip("\n") + " heap_free_pages=" + tail + "\n"
    assert contain.capacity_record(SSH, new) is None, tail
    assert contain.capacity_record(FSD, fsd_new) is None, tail
    assert agent.capacity(new) is None, tail
    assert LINK.search(new) is None, tail
for new in (HEAD + " heap_pages_peak=254 heap_free_pages=100 link=down\n",
            HEAD + " heap_pages_peak=254 heap_free_pages=100\n",
            LINE.rstrip("\n") + "  heap_free_pages=100\n"):
    assert contain.capacity_record(SSH, new) is None
    assert agent.capacity(new) is None
    assert LINK.search(new) is None
# New-contract fixture requires actual telemetry; historical optional parsing
# above is deliberately not evidence that an old producer implements A3.
new_record = contain.capacity_record(SSH, LINE.rstrip("\n") + " heap_free_pages=0\n")
assert new_record["heap_free_pages"] is not None
assert contain.capacity_record(SSH, LINE)["heap_free_pages"] is None
print("A3 CAPACITY CONSUMER PREPARATION OK")

# Production emitter contract: derive fixtures from actual Rust format strings.
# Existing evidence readers remain backwards-compatible; this gate requires both
# current emitters to name the new metric and bind it to the production accessor.
def producer_line(path, prefix, values, positional):
    source = path.read_text()
    literals = re.findall(r'"(' + prefix + r' CAPACITY boot=[^"\n]+)"', source)
    assert len(literals) == 1, (path, literals)
    template = literals[0]
    assert template.endswith(" heap_free_pages={heap_free_pages}"), template
    marker = "let heap_free_pages = absd_runtime::heap_free_pooled_pages();"
    assert source.count(marker) == 1 and source.index(marker) < source.index(template)
    return template.format(*positional, **values) + "\n"

for free in (0, 123):
    common = dict(boot=BOOT, heap_free_pages=free)
    ssh_line = producer_line(here.parent / "ssh/src/absd.rs", "SERVED",
                            dict(common, accepted_reclaimed=4, slots=0, pool=0),
                            (4, 0, 3, 58, 24, 1, 635, 254, "down"))
    fsd_line = producer_line(here.parent / "ssh/src/fsd_server.rs", "FSD",
                            dict(common, settled_releases=4, rotated_logs=0,
                                 bound=0, opens=0, draining=0), (1, 254))
    assert contain.capacity_record(SSH, ssh_line)["heap_free_pages"] == free
    assert contain.capacity_record(FSD, fsd_line)["heap_free_pages"] == free
    assert agent.capacity(ssh_line)["heap_free_pages"] == free
    # Current code that deliberately consumes only earlier fields keeps exactly
    # the same captured groups after the additional tail; not validation of A3.
    for filename, name, old, new in (
        ("c-kit-matrix.py", "SERVED", LINE, ssh_line),
        ("clang-guest-matrix.py", "SERVED", LINE, ssh_line),
        ("cports-matrix.py", "FSD_CAPACITY", FSD_LINE, fsd_line),
    ):
        pattern = source_pattern(here / filename, name)
        assert pattern.search(old).groups() == pattern.search(new).groups(), filename
    job_fsd = source_pattern(here / "agent-job.py", "FSD_CAPACITY")
    assert job_fsd.search(fsd_line).group(0) == fsd_line.rstrip("\n")
    # Boot-only recovery readers use inline expressions: exercise their actual
    # literal patterns without importing or running a recovery producer.
    tree = ast.parse((here / "survival-recovery.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "re.search" and node.args:
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                pattern = node.args[0].value
                if "CAPACITY boot=" in pattern:
                    line = fsd_line if "FSD CAPACITY" in pattern else ssh_line
                    assert re.search(pattern, line).group(1) == BOOT
runtime_source = (here.parent / "runtime/src/lib.rs").read_text()
assert re.search(r'pub fn heap_free_pooled_pages\(\) -> u64\s*\{\s*ALLOCATOR.free_pooled_pages\(\) as u64\s*\}', runtime_source)
print("A3 PRODUCTION EMITTER AND CURRENT CONSUMER CONTRACT OK")
