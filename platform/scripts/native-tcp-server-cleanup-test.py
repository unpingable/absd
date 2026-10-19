#!/usr/bin/env python3
"""Cleanup substitution controls; no real signals, namespace or guest creation.

Authored source only until the resource owner executes this exact file.
The fourteen packet/build/output artifact methods remain in their old file.
"""
import importlib.util
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("cleanup_matrix", Path(__file__).with_name("native-tcp-server-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CleanupControls(unittest.TestCase):
    def test_exited_leader_does_not_hide_remaining_owned_group(self):
        process = SimpleNamespace(pid=735001, returncode=0, poll=lambda: 0, wait=lambda timeout: 0)
        state, effects = {"present": True}, []

        def killpg(pgid, requested):
            self.assertEqual(pgid, process.pid)
            if not state["present"]:
                raise ProcessLookupError()
            if requested:
                effects.append(requested)
            if requested == signal.SIGKILL:
                state["present"] = False
            # The remaining member deliberately ignores TERM.

        with patch.object(m.os, "killpg", side_effect=killpg), \
             patch.object(m.time, "monotonic", side_effect=[0, 4, 5]):
            result = m.stop_group(process)
        self.assertEqual(effects, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(result["group_absent_verified"])
        self.assertEqual(result["leader_status"], 0)

    def test_mutated_then_timed_out_namespace_is_reconciled_and_unknown_refused(self):
        namespace = "absdtcps-owned-fixture"
        state, effects = {"present": False, "unknown": False, "pids": ""}, []

        def checked(argv):
            effects.append(argv)
            operation = argv[2]
            if operation == "add":
                state["present"] = True
                raise subprocess.TimeoutExpired(argv, 5)
            if state["unknown"]:
                raise subprocess.TimeoutExpired(argv, 5)
            if operation == "list":
                return SimpleNamespace(stdout=namespace + "\n" if state["present"] else "")
            self.assertEqual(argv[3], namespace)
            if operation == "pids":
                return SimpleNamespace(stdout=state["pids"])
            self.assertEqual(operation, "del")
            state["present"] = False
            return SimpleNamespace(stdout="")

        with patch.object(m, "checked", side_effect=checked):
            with self.assertRaises(subprocess.TimeoutExpired):
                m.checked(["ip", "netns", "add", namespace])
            result = m.cleanup_namespace(namespace, creation_attempted=True)
            self.assertTrue(result["deleted"] and result["absence_verified"])
            for unknown, pids in ((True, ""), (False, "735002\n")):
                state.update(present=True, unknown=unknown, pids=pids)
                before = len([v for v in effects if v[2] == "del"])
                with self.assertRaises((subprocess.TimeoutExpired, AssertionError)):
                    m.cleanup_namespace(namespace, creation_attempted=True)
                self.assertEqual(len([v for v in effects if v[2] == "del"]), before)
            state.update(present=True, unknown=False, pids="")
            with self.assertRaises(AssertionError):
                m.cleanup_namespace(namespace, creation_attempted=False)
            self.assertEqual(len([v for v in effects if v[2] == "del"]), before)


if __name__ == "__main__":
    unittest.main()
