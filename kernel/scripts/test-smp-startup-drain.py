#!/usr/bin/env python3
"""Run startup's actual wait and ordinary deadline/wake paths on a host.

Like test-serial-tx.py, substitute hardware boundaries, not scheduler policy.
Extract complete named Rust functions; reject missing/ambiguous definitions.
The fixture contains real process and run-queue types and controlled PIT/IPI
delivery. It does not execute privileged instructions or claim guest timing.
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT


def function(path, name):
    source = (SOURCE / path).read_text()
    matches = list(re.finditer(r"(?m)^(?:(?:pub(?:\([^\n]*?\))?|unsafe) )*fn "
                              + re.escape(name) + r"\(", source))
    assert len(matches) == 1, (path, name, len(matches))
    start = matches[0].start()
    opening = source.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[start:cursor]


def wait_body(name):
    source = function("src/smp_startup.rs", name)
    if "wait_for_departure();" in source:
        source = function("src/smp_startup.rs", "wait_for_departure")
    start = source.index("    crate::smp_user::startup_stop();")
    end = source.index("    crate::smp_user::startup_assert_fence();", start)
    end += len("    crate::smp_user::startup_assert_fence();")
    body = source[start:end]
    return body.replace("unsafe { core::arch::x86_64::_rdtsc() }", "crate::clock::tsc()")


def main():
    global SOURCE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT,
                        help="execute source from an unchanged baseline checkout")
    SOURCE = parser.parse_args().source_root.resolve()
    template = (ROOT / "scripts/fixtures/smp-startup-drain.rs").read_text()
    replacements = {
        "SINGLE_WAIT": wait_body("finish"),
        "MULTICORE_WAIT": wait_body("finish_multicore"),
        "WAKE_SLEEPERS": function("src/sched.rs", "wake_sleepers"),
        "DRAIN_DEPARTURES": function("src/sched.rs", "drain_ap_departures"),
        "MAKE_RUNNABLE": function("src/sched_rt.rs", "make_runnable"),
        "PUBLISH": function("src/modern_smp.rs", "publish"),
        "NOTIFY_PROCESS": function("src/smp_user.rs", "notify_process"),
        "QUIESCENT": function("src/smp_user.rs", "startup_quiescent"),
        "STARTUP_STOP": function("src/smp_user.rs", "startup_stop"),
        "DEADLINE": function("src/sched.rs", "deadline"),
        "KEY_FOR": function("src/modern_smp.rs", "key_for"),
        "PLACEMENT": function("src/modern_smp.rs", "placement_of_pid"),
        "ASSERT_ALL": function("src/modern_smp.rs", "assert_all"),
        "SELECT": function("src/modern_smp.rs", "select"),
        "STARTUP_DRAIN": (function("src/sched.rs", "drain_startup")
                          if "fn drain_startup(" in (SOURCE / "src/sched.rs").read_text()
                          else ""),
    }
    # Negative control changes only queue publication, keeping the real wake
    # and selection/consistency consumers intact.
    assert replacements["PUBLISH"].count("q.publish(k);") == 1
    replacements["PUBLISH"] = replacements["PUBLISH"].replace(
        "q.publish(k);", "if !OMIT.load(Ordering::Relaxed) { q.publish(k); }")
    for name, body in replacements.items():
        token = "// " + name
        assert template.count(token) == 1, name
        template = template.replace(token, body)
    template = template.replace("SOURCE_ROOT", str(SOURCE))
    with tempfile.TemporaryDirectory(prefix="absd-startup-drain-") as temporary:
        work = Path(temporary)
        source = work / "fixture.rs"
        binary = work / "fixture"
        source.write_text(template)
        subprocess.run(["rustc", "--edition=2024", "-C", "opt-level=1",
                        str(source), "-o", str(binary)], check=True, cwd=ROOT)
        cases = ["due", "single", "not-due", "retired", "stop-requested",
                 "owned", "no-publish", "no-notify"]
        for case in cases:
            subprocess.run([str(binary), case], check=True, timeout=15)
    print(f"STARTUP DRAIN HOST TEST OK cases={len(cases)}")


if __name__ == "__main__":
    main()
