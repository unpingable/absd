#!/usr/bin/env python3
"""Check the closed boot-time CPU identity cache receipt.

The kernel's raw APIC/MSR checks establish these records. This host checker
validates the receipt and its chronology; it does not independently validate
hardware identity or cookie provenance.
"""
import re
import sys
from pathlib import Path


COOKIE = 0xAB5D0100
PREFIX = "SMP CPU CACHE "


def must(ok, message):
    if not ok:
        raise AssertionError(message)


def decimal(value, name):
    must(re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
         f"noncanonical {name}")
    return int(value)


def parse(lines, cpus):
    must(cpus in (1, 2, 4, 6), "unsupported CPU count")
    must(lines.count("ABSD BOOT OK") == 1, "unique successful boot missing")
    boot = lines.index("ABSD BOOT OK")
    must(not any(re.search(r"PANIC|KERNEL FAULT|FAILED", line) for line in lines),
         "failure record present")
    must(not any(line.startswith("SMP COMMON ") for line in lines),
         "common-path observer records present in cache-only receipt")

    cache_rows = [(i, line) for i, line in enumerate(lines)
                  if line.startswith(PREFIX)]
    enabled = []
    binds = []
    audits = []
    for i, line in cache_rows:
        m = re.fullmatch(
            r"SMP CPU CACHE ENABLED cpus=([0-9]+) ready=([0-9]+) immutable=1", line)
        if m:
            enabled.append((i, decimal(m[1], "enabled CPU count"),
                            decimal(m[2], "ready mask")))
            continue
        m = re.fullmatch(
            r"SMP CPU CACHE BIND cpu=([0-9]+) apic=([0-9]+) aux=([0-9]+) raw-validated=1",
            line)
        if m:
            binds.append((i, *(decimal(m[k], "binding field") for k in (1, 2, 3))))
            continue
        m = re.fullmatch(
            r"SMP CPU CACHE AUDIT cpu=([0-9]+) raw-match=1 before-user=1", line)
        must(m is not None, "unknown or malformed CPU cache record")
        audits.append((i, decimal(m[1], "audit CPU")))

    must(len(enabled) == 1, "enabled record missing/duplicate")
    enabled_i, enabled_cpus, ready = enabled[0]
    must(enabled_cpus == cpus and ready == (1 << cpus) - 1,
         "enabled CPU count/readiness mismatch")
    must(len(binds) == cpus, "binding census mismatch")
    expected_binds = [(i, i, COOKIE | i) for i in range(cpus)]
    actual_binds = [(cpu, apic, aux) for _, cpu, apic, aux in binds]
    must(actual_binds == expected_binds, "binding identity/AUX mismatch")
    bind_indices = [i for i, *_ in binds]
    must(enabled_i < bind_indices[0], "enabled record must precede bindings")
    must(bind_indices == list(range(bind_indices[0], bind_indices[0] + cpus)),
         "binding records are not contiguous")

    must(len(audits) == cpus, "audit census mismatch")
    audit_cpus = [cpu for _, cpu in audits]
    must(sorted(audit_cpus) == list(range(cpus)), "audit CPU set/uniqueness mismatch")
    audit_indices = [i for i, _ in audits]
    bsp_audit = next(i for i, cpu in audits if cpu == 0)
    must(bind_indices[-1] < bsp_audit, "BSP audit precedes complete binding census")
    must(all(i > bind_indices[-1] for i in audit_indices),
         "audit precedes complete binding census")
    must(all(i < boot for i in audit_indices), "audit after successful boot")
    for audit_i, cpu in audits:
        if cpu == 0:
            continue
        starts = [i for i, line in enumerate(lines)
                  if re.match(rf"SMP TIMER START cpu={cpu}(?: |$)", line)]
        must(len(starts) == 1 and audit_i < starts[0],
             "AP audit must precede its own timer/scheduler entry")
    phases = [i for i, line in enumerate(lines)
              if line.startswith(("SMP APP SCALE START ", "SMP SCALE START "))]
    if phases:
        must(max(audit_indices) < min(phases), "audit entered timed phase")
    users = [i for i, line in enumerate(lines) if line.startswith("SMP USER ")]
    if users:
        must(bsp_audit < min(users), "BSP audit is not before user dispatch")
    must(enabled_i < bind_indices[0] < bsp_audit < boot,
         "cache publication chronology mismatch")
    return True


def rejected(lines, cpus):
    try:
        parse(lines, cpus)
    except (AssertionError, StopIteration):
        return True
    return False


def controls(lines, cpus):
    rows = list(lines)
    bind_positions = [i for i, x in enumerate(rows) if x.startswith(PREFIX + "BIND ")]
    audit_positions = [i for i, x in enumerate(rows) if x.startswith(PREFIX + "AUDIT ")]
    enabled_i = next(i for i, x in enumerate(rows) if x.startswith(PREFIX + "ENABLED "))
    must(bind_positions and audit_positions, "receipt controls require positive records")
    count = 0

    changed = rows.copy()
    changed.pop(bind_positions[-1])
    must(rejected(changed, cpus), "dropped binding control accepted")
    count += 1

    changed = rows.copy()
    changed.pop(audit_positions[-1])
    must(rejected(changed, cpus), "dropped audit control accepted")
    count += 1

    changed = rows.copy()
    bind_i = bind_positions[-1]
    m = re.fullmatch(
        r"SMP CPU CACHE BIND cpu=([0-9]+) apic=([0-9]+) aux=([0-9]+) raw-validated=1",
        changed[bind_i])
    cpu = int(m[1])
    # For N>1 use another admitted logical CPU; for the UP capture, use the
    # same valid cookie encoding for CPU1 (outside the one-CPU admission).
    other = (cpu + 1) % cpus if cpus > 1 else 1
    changed[bind_i] = (f"SMP CPU CACHE BIND cpu={m[1]} apic={m[2]} "
                       f"aux={COOKIE | other} raw-validated=1")
    must(rejected(changed, cpus), "crosswired valid-cookie control accepted")
    count += 1

    changed = rows.copy()
    record = changed.pop(enabled_i)
    first_bind = next(i for i, x in enumerate(changed) if x.startswith(PREFIX + "BIND "))
    changed.insert(first_bind + 1, record)
    must(rejected(changed, cpus), "late enabled-record control accepted")
    count += 1

    changed = rows.copy()
    audit_i = next(i for i, x in enumerate(changed) if x.startswith(PREFIX + "AUDIT "))
    changed.insert(audit_i + 1, changed[audit_i])
    must(rejected(changed, cpus), "duplicate audit control accepted")
    count += 1

    if cpus > 1:
        changed = rows.copy()
        audit_i = next(i for i, x in enumerate(changed)
                       if x == "SMP CPU CACHE AUDIT cpu=1 raw-match=1 before-user=1")
        record = changed.pop(audit_i)
        timer_i = next(i for i, x in enumerate(changed)
                       if re.match(r"SMP TIMER START cpu=1(?: |$)", x))
        changed.insert(timer_i + 1, record)
    else:
        changed = rows.copy()
        audit_i = next(i for i, x in enumerate(changed)
                       if x.startswith(PREFIX + "AUDIT "))
        record = changed.pop(audit_i)
        changed.insert(changed.index("ABSD BOOT OK") + 1, record)
    must(rejected(changed, cpus), "late audit control accepted")
    count += 1
    must(count == 6, "receipt control census mismatch")
    return count


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: check-smp-cpu-cache.py SERIAL CPUS(1/2/4/6)")
    cpus = int(sys.argv[2])
    lines = Path(sys.argv[1]).read_text(errors="replace").splitlines()
    parse(lines, cpus)
    count = controls(lines, cpus)
    print(f"SMP CPU cache receipt accepted cpus={cpus} controls={count}")


if __name__ == "__main__":
    main()
