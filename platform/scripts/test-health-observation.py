#!/usr/bin/env python3
"""Shared vectors, host renderer/source controls, and native-output validation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("health_validator", ROOT / "scripts/validate-health-json.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
VECTORS = ROOT / "docs/observations-health/vectors.json"


class Conformance(unittest.TestCase):
    def test_shared_vectors(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        self.assertGreaterEqual(len(cases), 38)
        for case in cases:
            with self.subTest(case=case["name"]):
                raw = case["input_utf8"].encode("utf-8")
                if case["expected"] == "reject":
                    with self.assertRaises((ValueError, TypeError, KeyError, UnicodeError)):
                        validator.validate(raw)
                else:
                    self.assertEqual(validator.validate(raw), case["expected"].removeprefix("accept_"))

    def test_source_projection_has_no_new_observation_calls(self):
        src = (ROOT / "src/bin/health.rs").read_text()
        json_path = src[src.index("fn json_health()"):src.index("fn read(")]
        for surface in ("frame_stats", "resource_census", "wall_clock", "nic::", "metadata("):
            self.assertNotIn(surface, json_path)
        self.assertNotIn("unwrap_or_default", json_path)
        self.assertIn('(_, Err(issue)) => Err(*issue)', json_path)


def validate_outputs(path):
    count = 0
    with path.open("rb") as stream:
        for raw in stream:
            if not raw.strip():
                continue
            validator.validate(raw)
            def sorted_keys(value):
                if isinstance(value, dict):
                    if list(value) != sorted(value):
                        raise ValueError("renderer object keys are not lexically sorted")
                    for child in value.values():
                        sorted_keys(child)
                elif isinstance(value, list):
                    for child in value:
                        sorted_keys(child)
            sorted_keys(json.loads(raw))
            count += 1
    if count == 0:
        raise ValueError("no renderer outputs supplied")
    print(f"HEALTH VALIDATED OUTPUTS {count} path={path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", action="store_true", help="also compile and exercise pure Rust projection")
    parser.add_argument("--rendered-jsonl", type=Path, help="validate every supplied native output")
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Conformance))
    if not result.wasSuccessful():
        return 1
    if args.host:
        work = Path(os.environ.get("ABSD_HEALTH_HOST_WORK", ROOT / ".host-target/health-observation"))
        work.mkdir(parents=True, exist_ok=True)
        output = work / "renderer-output.jsonl"
        env = dict(os.environ, ABSD_HEALTH_RENDERED_OUTPUT=str(output), CARGO_TARGET_DIR=str(work / "target"))
        env.pop("RUSTFLAGS", None)
        cmd = ["cargo", "+1.95.0", "test", "--offline", "--locked", "--manifest-path",
               str(ROOT / "tests/Cargo.toml"), "--target", "x86_64-unknown-linux-gnu"]
        subprocess.run(cmd, cwd=ROOT, env=env, check=True)
        validate_outputs(output)
    if args.rendered_jsonl:
        validate_outputs(args.rendered_jsonl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
