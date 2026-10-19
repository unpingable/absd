#!/usr/bin/env python3
"""Bounded lexical source guard, reusing the admitted TLS guard unchanged.

This checks the named configuration source, not arbitrary Rust semantics.
Independent review and actual native evidence remain separate requirements.
"""
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tls_source_guard", ROOT / "scripts/check-native-tls-source.py")
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


def main():
    if sys.flags.optimize or __import__("os").environ.get("PYTHONOPTIMIZE"):
        raise tls.Refusal("optimized Python refused")
    files = sorted((ROOT / "quic/src").rglob("*.rs"))
    if (ROOT / "quic/build.rs").exists() or any(p.is_symlink() for p in files):
        raise tls.Refusal("generated source or symlink requires review")
    sources = {str(p.relative_to(ROOT)): p.read_text() for p in files}
    # Only the lexical guard's canonical engine key changes; its implementation
    # and TLS verifier/version/resumption restrictions stay byte-identical.
    canonical = dict(sources)
    canonical["tls/src/engine.rs"] = canonical.pop("quic/src/engine.rs")
    # The one new reviewed macro refuses absent native custom-backend cfg at
    # compile time. It cannot generate protocol configuration.
    tls.ALLOWED_MACROS.add("compile_error")
    tls.inspect_sources(canonical)
    code = tls.masked(sources["quic/src/engine.rs"])
    for name, expression in {
        "one endpoint": r"Endpoint\s*::\s*new\s*\(",
        "one connect": r"endpoint\s*\.\s*connect\s*\(",
        "explicit seeded endpoint": r"\.rng_seed\s*\(\s*Some\s*\(",
        "explicit CID factory": r"\.cid_generator\s*\(",
        "explicit initial CID": r"\.initial_dst_cid_provider\s*\(",
        "no cached tokens": r"NoneTokenStore",
        "fixed MTU": r"mtu_discovery_config\s*\(\s*None\s*\)",
        "no GSO": r"enable_segmentation_offload\s*\(\s*false\s*\)",
        "NewReno": r"NewRenoConfig\s*::\s*default\s*\(",
    }.items():
        if len(re.findall(expression, code)) != 1:
            raise tls.Refusal("configuration needs exactly one " + name)
    words = set(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", code))
    if words & {"ServerConfig", "enable_0rtt", "into_0rtt", "BbrConfig", "CubicConfig", "send_datagram"}:
        raise tls.Refusal("unadmitted protocol profile")
    print(json.dumps({"disposition": "PASS", "files": sorted(sources),
                      "scope": "Lexical configuration source only; no compilation or protocol execution"}))


if __name__ == "__main__":
    try:
        main()
    except (tls.Refusal, OSError, UnicodeError) as error:
        print("native QUIC source guard: " + str(error), file=sys.stderr)
        sys.exit(1)
