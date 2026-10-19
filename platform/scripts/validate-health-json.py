#!/usr/bin/env python3
"""Validator for the closed health v1 result, including shared vector controls."""
import json
import re
import sys
from pathlib import Path

SCHEMA = "absd.observation_health.v1"
MAX_BYTES = 8192
FACTS = {
    "boot.id": ("kernel", "boot", "kernel_boot_id", "not_applicable"),
    "boot.ticks": ("kernel", "boot", "kernel_ticks", "not_applicable"),
    "fsd.release": ("fsd", "held-fsd", "fsd_version", "not_applicable"),
    "fsd.recovery": ("fsd", "held-fsd", "fsd_log_current_and_rotated", "unknown"),
}
REASONS = {
    "boot_id_refused", "fsd_absent", "fsd_refused", "recovery_not_retained",
    "recovery_malformed", "boot_id_unavailable", "wrong_boot", "field_out_of_bounds",
    "io_error", "no_answer", "malformed", "protocol_mismatch", "release_mismatch",
    "unsupported", "not_collected",
}
FSD_REFUSALS = {
    ("unavailable", "fsd_absent"), ("unavailable", "no_answer"),
    ("unavailable", "io_error"), ("unavailable", "fsd_refused"),
    ("denied", "fsd_refused"), ("unsupported", "unsupported"),
    ("malformed", "malformed"), ("malformed", "protocol_mismatch"),
    ("malformed", "release_mismatch"),
}
FACT_REFUSALS = {
    "boot.id": {("unavailable", "boot_id_refused")},
    "boot.ticks": set(),
    "fsd.release": FSD_REFUSALS | {("malformed", "field_out_of_bounds")},
    "fsd.recovery": FSD_REFUSALS | {
        ("unavailable", "recovery_not_retained"),
        ("unavailable", "boot_id_unavailable"),
        ("malformed", "recovery_malformed"),
    },
}


def require(condition, rule):
    if not condition:
        raise ValueError(rule)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()), "closed object fields")


def counter(value):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
            "canonical decimal string")
    require(len(value) <= 20 and int(value) <= (1 << 64) - 1, "u64 counter bound")
    return int(value)


def boot_id(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def strings(value):
    if type(value) is str:
        require(len(value.encode("utf-8")) <= 128, "decoded string bound")
    elif type(value) is dict:
        for key, child in value.items():
            strings(key)
            strings(child)
    elif type(value) is list:
        for child in value:
            strings(child)


def validate(raw):
    """Return complete/partial; fail closed on malformed or ambiguous input."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "document byte bound")
    def nonfinite(_):
        raise ValueError("nonfinite number")
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs, parse_constant=nonfinite)
    strings(doc)
    keys(doc, "schema scope status boot_id interval producer facts")
    require(doc["schema"] == SCHEMA and doc["scope"] == "health", "known version/scope")
    boot = doc["boot_id"]
    require(boot is None or boot_id(boot), "boot identity")
    keys(doc["interval"], "clock start end")
    require(doc["interval"]["clock"] == "kernel_ticks", "clock domain")
    start, end = counter(doc["interval"]["start"]), counter(doc["interval"]["end"])
    require(start <= end, "acquisition ordering")
    keys(doc["producer"], "role pid implementation_ref")
    require(doc["producer"]["role"] == "health" and doc["producer"]["implementation_ref"] is None,
            "producer role/unknown executable identity")
    if doc["producer"]["pid"] is not None:
        counter(doc["producer"]["pid"])
    facts = doc["facts"]
    require(type(facts) is list and len(facts) == 4, "fixed four facts")
    seen = set()
    complete = True
    for fact in facts:
        keys(fact, "id owner subject source availability value reason loss lifetime_ref implementation_ref freshness")
        fid = fact["id"]
        require(type(fid) is str and fid in FACTS and fid not in seen, "unique known fact")
        seen.add(fid)
        require(tuple(fact[k] for k in ("owner", "subject", "source", "loss")) == FACTS[fid],
                "owner/source/subject/loss correspondence")
        require(fact["implementation_ref"] is None, "unknown owner executable identity")
        availability = fact["availability"]
        require(availability in ("known", "unavailable", "denied", "unsupported", "malformed", "stale"),
                "availability vocabulary")
        value = fact["value"]
        expected_lifetime = None
        if availability != "known":
            complete = False
            require(value is None and fact["reason"] in REASONS and fact["freshness"] == "unknown",
                    "explicit unavailable fact")
            require((availability, fact["reason"]) in FACT_REFUSALS[fid],
                    "fact/availability/reason correspondence")
            if fact["reason"] == "boot_id_unavailable":
                require(boot is None, "boot unavailable reason requires unknown boot")
            if fid == "boot.id":
                require(boot is None, "unknown boot context")
        else:
            require(fact["reason"] is None and value is not None, "known fact has no refusal")
            require(fact["freshness"] == ("record_for_current_boot" if fid == "fsd.recovery"
                                           else "sampled_during_interval"), "fact freshness")
            if fid == "boot.id":
                require(boot_id(value) and value == boot, "boot fact context join")
            elif fid == "boot.ticks":
                require(start <= counter(value) <= end, "tick within acquisition")
            elif fid == "fsd.release":
                require(type(value) is str and re.fullmatch(r"[a-z0-9.-]{1,64}", value) is not None,
                        "existing release identity grammar")
            else:
                keys(value, "boot_id seq streak previous")
                require(boot is not None and value["boot_id"] == boot, "recovery boot join")
                counter(value["seq"])
                counter(value["streak"])
                require(value["previous"] in ("none", "ended", "failed", "not_ready"), "previous outcome")
                expected_lifetime = f"boot:{boot}/recovery:{value['seq']}"
            if fid in ("boot.id", "boot.ticks") and boot is not None:
                expected_lifetime = f"boot:{boot}"
        require(fact["lifetime_ref"] == expected_lifetime, "observed lifetime correspondence")
        if fid == "fsd.recovery" and boot is None:
            require(availability == "unavailable" and fact["reason"] == "boot_id_unavailable",
                    "no recovery without boot identity")
    status = "complete" if complete else "partial"
    require(doc["status"] == status, "fixed-subset status")
    return status


if __name__ == "__main__":
    try:
        for path in sys.argv[1:]:
            print(path, validate(Path(path).read_bytes()))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        sys.exit(f"health JSON refused: {exc}")
