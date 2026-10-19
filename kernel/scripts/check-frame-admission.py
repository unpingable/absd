#!/usr/bin/env python3
"""Check the two-call wire contract, optionally against a paired platform.

The platform supplies a check-only TOML file with exactly the same keys.
No runtime/libc wrappers are installed. Parser support is checked separately
against its broker source; a constant alone does not prove role-18 support.
"""
import argparse
import ast
import operator
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


def integer(expression):
    def value(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -value(node.operand)
        operations = {ast.LShift: operator.lshift, ast.Sub: operator.sub}
        if isinstance(node, ast.BinOp) and type(node.op) in operations:
            return operations[type(node.op)](value(node.left), value(node.right))
        raise ValueError(f"unsupported constant expression: {expression}")
    return value(ast.parse(expression, mode="eval").body)


def compare(expected, actual):
    if actual != expected:
        bad = sorted(k for k in expected.keys() | actual.keys()
                     if actual.get(k) != expected.get(k))
        raise ValueError("frame ABI mismatch: " + ", ".join(bad))


def parser_support(source):
    if not re.search(r"pub const LIVENESS: u8 = 18;", source):
        raise ValueError("missing role-18 constant")
    if not re.search(r"role::LIVENESS\s*=>\s*&mut startup\.liveness", source):
        raise ValueError("missing role-18 parser arm")


def kernel_contract():
    expected = tomllib.loads((ROOT / "abi/frame-admission-v0.toml").read_text())
    source = (ROOT / "abi/src/syscall.rs").read_text()
    actual = {name: integer(expression) for name, expression in
              re.findall(r"pub const (\w+): \w+ = ([^;]+);", source)
              if name in expected}
    actual["endian"] = "little"  # Exact byte encoding is exercised by the Rust wire test.
    role = re.search(r"pub const ROLE_LIVENESS: u8 = (\d+);",
                     (ROOT / "user/src/broker.rs").read_text())
    actual["role_liveness"] = int(role[1]) if role else None
    compare(expected, actual)
    return expected


class MismatchTests(unittest.TestCase):
    def test_number_cap_and_role_mismatches_are_refused(self):
        expected = kernel_contract()
        for name in ("SYS_FRAME_ADMIT_SELF", "SYS_SPAWN_RESERVED_COPY",
                     "MAX_FRAME_ADMISSION_FRAMES", "role_liveness"):
            with self.subTest(name=name):
                mutant = dict(expected)
                mutant[name] += 1
                with self.assertRaises(ValueError):
                    compare(expected, mutant)

    def test_role_constant_without_parser_is_refused(self):
        with self.assertRaises(ValueError):
            parser_support("pub const LIVENESS: u8 = 18;")
        parser_support("pub const LIVENESS: u8 = 18; role::LIVENESS => &mut startup.liveness,")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path)
    parser.add_argument("--platform-contract", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
    else:
        try:
            expected = kernel_contract()
            if bool(args.platform) != bool(args.platform_contract):
                raise ValueError("paired check requires both --platform and --platform-contract")
            if args.platform:
                compare(expected, tomllib.loads(args.platform_contract.read_text()))
                parser_support((args.platform / "broker/src/lib.rs").read_text())
            print("FRAME ABI OK scope=" + ("paired" if args.platform else "kernel-only"))
        except (ValueError, OSError) as error:
            parser.exit(1, f"{error}\n")
