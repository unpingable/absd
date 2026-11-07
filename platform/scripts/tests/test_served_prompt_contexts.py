#!/usr/bin/env python3
"""Replay the live output predicates without launching a served occurrence.

The non-PTY bytes are the steward's attempt02 capture at 48e092b9. Compile
the actual consumer expressions, so a change at their call sites is tested
as well as the prompt constants. This does not qualify SSH or the emulator.
"""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CAPTURED = b'absd$ stop refused runtime=-9 retired=-38 guessed=256/256\nabsd$ 0\nabsd$ '


def source(name):
    path = ROOT / 'scripts' / name
    tree = ast.parse(path.read_text())
    values = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            if n.targets[0].id in ('PROMPT', 'PTY_PROMPT'):
                values[n.targets[0].id] = eval(compile(ast.Expression(n.value), str(path), 'eval'), values)
    return path, tree, values


class PromptContexts(unittest.TestCase):
    def stop_predicate(self, out):
        path, tree, values = source('served-matrix.py')
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.args
                    and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value == "a shell's child cannot stop the machine")
        assignments = [next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                            and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
                       for name in ('refusal', 'shown')]
        scope = dict(values, rc=0, out=out, err=b'', re=re)
        exec(compile(ast.Module(body=assignments, type_ignores=[]), str(path), 'exec'), scope)
        return eval(compile(ast.Expression(call.args[1]), str(path), 'eval'), scope)

    def test_captured_nonpty_refusal_and_status_pass(self):
        self.assertTrue(self.stop_predicate(CAPTURED))

    def test_nonpty_wrong_status_refusal_or_transport_do_not_pass(self):
        for out in (CAPTURED.replace(b'\nabsd$ 0\n', b'\nabsd$ 1\n'),
                    CAPTURED.replace(b'runtime=-9', b'runtime=-8'),
                    b'\x1b[?2004h' + CAPTURED):
            with self.subTest(out=out):
                self.assertFalse(self.stop_predicate(out))

    def test_manual_guard_rejects_plain_prompt_text(self):
        path, tree, values = source('cmds-matrix.py')
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.args
                    and isinstance(n.args[0], ast.JoinedStr)
                    and any(isinstance(v, ast.Constant) and v.value == ': no prompt text inside the page'
                            for v in n.args[0].values))
        # A deterministic page fixture, not claimed as a captured native page.
        scope = dict(values, pages={'intro': b'INTRO(1)\nNAME\nintro\nabsd$ echo\n'}, key='intro')
        self.assertFalse(eval(compile(ast.Expression(call.args[1]), str(path), 'eval'), scope))


if __name__ == '__main__':
    unittest.main()
