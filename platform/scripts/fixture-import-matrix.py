#!/usr/bin/env python3
"""Native per-entry import commits and real Clang-fixture append timing.

Uses an owned VM's fresh work directory. Kernel/source/executable identities,
raw build/boot logs, input identities and terminal results stay with the run.
No compiler or SSH service from the opaque Clang input fixture is executed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tarfile
import time
import traceback

CUTS = ("directory-created", "created", "prefix-copied", "input-written", "synced", "verified", "renamed")
PATH = "/atomic/file"
KEEP = "/atomic/keep"
OLD = b"committed prefix\n" * 300
# Keep phase-stop input below init's pipe capacity so a stopped worker does
# not strand upstream input before init drains its boundary notification.
# The full Clang fixture separately exercises normal 1 MiB streaming boots.
NEW = b"verified suffix\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--importer-dir", required=True)
    ap.add_argument("--clang-bundle", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", choices=("boundaries", "clang", "all"), default="all")
    args = ap.parse_args()
    source = pathlib.Path(args.platform).resolve()
    kernel = pathlib.Path(args.kernel).resolve()
    elfs = pathlib.Path(args.importer_dir).resolve()
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "scripts"))
    # The audited policies, from the same tree release.py and operator_image.py load them.
    from served_kernel import kernel_make
    from served_ram import served_qemu
    rel = load(source / "scripts/release.py", "fixture_matrix_release")
    em, oi, fs = rel.em, rel.oi, rel.absd_fs
    result = {"source": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
              "kernel": subprocess.check_output(["git", "-C", str(kernel), "rev-parse", "HEAD"], text=True).strip(),
              "elfs": {p.name: sha(p.read_bytes()) for p in elfs.glob("*.elf")}, "cases": [], "boots": []}

    def save(phase):
        (work / "PROGRESS.json").write_text(json.dumps({"phase": phase, "cases": len(result["cases"]),
            "boots": len(result["boots"]), "last": result["boots"][-1] if result["boots"] else None}, indent=2) + "\n")

    def require(ok, message):
        if not ok:
            raise RuntimeError(message)

    def read_image(image):
        region = fs.fs_region(image, image.stat().st_size // 512)
        selected = fs.select(region)
        nodes = fs.tree(region, selected)
        files = {p: fs.content(region, selected, n) for p, n in nodes.items() if not n["dir"]}
        return selected, nodes, files

    def blank(directory, size=64 << 20):
        directory.mkdir(parents=True, exist_ok=False)
        image = directory / rel.IMAGE
        with image.open("wb") as handle:
            handle.truncate(size)
        return image

    def boot(label, step, image, entries, variant="normal", raw=None):
        save(label)
        directory = work / "boots" / label
        directory.mkdir(parents=True, exist_ok=False)
        stream = em.stream(entries) if raw is None else raw
        input_path = directory / "input.bin"
        input_path.write_bytes(stream)
        elf = elfs / f"fixture-import-{variant}.elf"
        argv = [*kernel_make(), "--no-print-directory", "-C", str(kernel), "durable-iso",
                f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={elf}", f"EXTERNAL_INPUT={input_path}",
                "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT=", "DURABLE_OPTIONS=", "FILE_SERVER_ELF="]
        built = time.monotonic()
        with (directory / "build.log").open("x") as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=True)
        build_seconds = time.monotonic() - built
        iso = kernel / "build/durable" / f"absd-durable-{step}.iso"
        serial = directory / "serial.log"
        command = [str(kernel / "scripts/durable-boot.sh"), str(iso), str(image), str(serial), "600",
                   *served_qemu(rel.QEMU)]
        start = time.monotonic()
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        try:
            out, err = proc.communicate(timeout=640)
        except BaseException:
            # Only this invocation's new process group; no name-based signals.
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=10)
            raise
        seconds = time.monotonic() - start
        require(proc.returncode == 0, f"{label}: boot helper {proc.returncode}: {err}")
        require(not rel.image_holders(image), f"{label}: disk writer has not ended")
        text = rel.ssh_absd.captured(serial.read_bytes())
        accounting = re.findall(r"^DURABLE status=(-?\d+) frames=0 processes=0 cells=0 pipes=0 ",
                                serial.read_text(errors="replace"), re.M)
        require(bool(accounting), f"{label}: missing zero resource accounting")
        record = {"label": label, "step": step, "variant": variant, "status": out.strip(), "seconds": seconds,
                  "build_seconds": build_seconds, "input_sha256": sha(stream), "elf_sha256": sha(elf.read_bytes()),
                  "iso_sha256": sha(iso.read_bytes()), "serial_sha256": sha(serial.read_bytes()),
                  "accounting_status": accounting[-1]}
        result["boots"].append(record)
        (directory / "BOOT.json").write_text(json.dumps(record, indent=2) + "\n")
        # Exact stream is reconstructible from the named input bundle or OLD/NEW
        # constants and recorded operation; preserve its hash, not duplicate blobs.
        input_path.unlink()
        return record, text

    def cleanup_observed(arguments, label):
        original = rel.importer_boot
        captured = []
        def observe(script, iso, image, scratch, index, count, step, entries, log, plan_record=None):
            serial = pathlib.Path(scratch) / f"import-{index:03d}.serial.log"
            try:
                returned = original(script, iso, image, scratch, index, count, step, entries, log, plan_record)
            finally:
                if serial.is_file():
                    dest = work / "boots" / (label + "-cleanup.serial.log")
                    dest.write_bytes(serial.read_bytes())
                    captured.append({"path": str(dest.relative_to(work)), "sha256": sha(dest.read_bytes())})
            require(bool(re.search(r"^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                                   serial.read_text(errors="replace"), re.M)), label + " cleanup accounting")
            return returned
        rel.importer_boot = observe
        try:
            rel.cmd_discard_import_temp(arguments, log=lambda message: print(message, flush=True))
        finally:
            rel.importer_boot = original
        return captured

    def fixture_release():
        directory = work / "cleanup-release"
        directory.mkdir()
        (directory / "tree").mkdir()
        (directory / "release").write_text(rel.record_text("import-control"))
        for name in (rel.ISO, "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf"):
            (directory / name).write_bytes(b"opaque host-tool fixture; never booted\n")
        (directory / "fixture-import.elf").write_bytes((elfs / "fixture-import-normal.elf").read_bytes())
        doc = {"schema": "absd-release-manifest/2", "release": {"id": "import-control"},
               "identity": rel.IDENTITY, "source": {"kernel_commit": result["kernel"]},
               "artifacts": {"files": {p.name: {"sha256": sha(p.read_bytes())} for p in directory.iterdir()
                                      if p.is_file()}}}
        # This fixture needs only the importer, record and existing step-5 route.
        lines = [f'schema = "{doc["schema"]}"', '[release]', 'id = "import-control"', '[identity]']
        lines += [f"{key} = {value}" for key, value in rel.IDENTITY.items()]
        lines += ['[source]', f'kernel_commit = "{result["kernel"]}"']
        for name, item in doc["artifacts"]["files"].items():
            lines += [f'[artifacts.files."{name}"]', f'sha256 = "{item["sha256"]}"']
        (directory / "release-manifest.toml").write_text("\n".join(lines) + "\n")
        return directory

    started = time.monotonic()
    try:
        release = fixture_release()
        if args.only in ("boundaries", "all"):
            for step in (1, 2, 3, 4):
                for variant in (*CUTS, "normal", "bad-digest"):
                    label = f"step{step}-{variant}"
                    image = blank(work / "images" / label)
                    expected_old = {}
                    if step != 1:
                        initial = [(KEEP, b"untouched sibling\n")]
                        if step >= 3:
                            initial.append((PATH, OLD))
                        record, text = boot(label + "-prepare", 1, image, initial)
                        require(record["status"] == "3" and "FIXTURE IMPORT OK" in text, label + " preparation")
                        expected_old = dict(initial)
                    candidate = OLD + NEW if step == 3 else NEW
                    raw = None
                    if variant == "bad-digest":
                        raw = bytearray(em.stream([(PATH, NEW)]))
                        offset = 8 + 2 + len(PATH.encode()) + 8
                        raw[offset] ^= 1
                    record, text = boot(label, step, image, [(PATH, NEW)],
                                        variant=variant if variant in CUTS else "normal", raw=raw)
                    selected, nodes, files = read_image(image)
                    temp_identity, cleanup_evidence = None, []
                    if variant == "normal":
                        require(record["status"] == "3" and "FIXTURE IMPORT OK files=1" in text, label + " success")
                        expected = {**expected_old, PATH: candidate}
                    elif variant == "bad-digest":
                        require(record["status"] == "7" and "digest mismatch" in text, label + " named refusal")
                        expected = expected_old
                    else:
                        require(record["status"] == "7" and f"STOP boundary={variant}" in text, label + " stop")
                        expected = {**expected_old, PATH: candidate} if variant == "renamed" else expected_old
                    actual = {p: data for p, data in files.items() if not em.reserved_import_path(p)}
                    require(actual == expected, label + " final pathname changed before verified commit")
                    temporary = [p for p, n in nodes.items() if n["dir"]
                                 and re.fullmatch(r"\.absd-import-[0-9a-f]{4}", pathlib.PurePosixPath(p).name)]
                    if variant in CUTS:
                        require(len(temporary) == 1, label + " temp ownership record")
                        identity = rel.import_temp_identity(rel.Target(image.parent), temporary[0])
                        cleanup = rel.argparse.Namespace(target=str(image.parent), release=str(release),
                            kernel=str(kernel), directory=temporary[0], fs_id=identity["fs_id"],
                            serial=identity["serial"], bytes=identity["bytes"], sha256=identity["sha256"])
                        temp_identity = identity
                        cleanup_evidence = cleanup_observed(cleanup, label)
                        _, after_nodes, after_files = read_image(image)
                        require(after_files == expected, label + " cleanup changed another file")
                        require(not any(em.reserved_import_path(p) for p in after_nodes), label + " unresolved temp")
                    else:
                        require(not temporary, label + " leftover temp on completed/refused input")
                    case = {"name": label, "verdict": "PASS", "boot_seconds": record["seconds"],
                            "expected_file_digests": {p: sha(data) for p, data in expected.items()},
                            "observed_file_digests": {p: sha(data) for p, data in actual.items()},
                            "temporary_identity": temp_identity, "cleanup_evidence": cleanup_evidence}
                    with (image.parent / "CASE.json").open("x") as output:
                        json.dump(case, output, indent=2); output.write("\n")
                    result["cases"].append(case)
                    # The exact replay inputs and proof are retained; the disk is
                    # disposable only after it is halted and the case is recorded.
                    (image.parent / "IMAGE-RECEIPT.json").write_text(json.dumps({"sha256": sha(image.read_bytes()),
                        "case_sha256": sha((image.parent / "CASE.json").read_bytes()),
                        "disposition": "case recorded, no remaining replay dependency on mutable disk"}) + "\n")
                    image.unlink()
        if args.only in ("clang", "all"):
            with tarfile.open(args.clang_bundle, "r:gz") as archive:
                manifest = json.load(archive.extractfile("MANIFEST.json"))
                files = []
                for row in manifest["files"]:
                    data = archive.extractfile(row["member"]).read()
                    require(len(data) == row["bytes"] and sha(data) == row["sha256"], "Clang opaque input identity")
                    files.append((row["path"], data))
            plan = em.import_plan(files)
            records = em.import_plan_records(plan)
            size = manifest["smallest_fixture"]
            image = blank(work / "images/clang", size)
            em.check_import_capacity(image, plan)
            begin = time.monotonic()
            last_cc1 = None
            for index, ((step, entries), detail) in enumerate(zip(plan, records), 1):
                record, text = boot(f"clang-{index:03d}", step, image, entries)
                require(record["status"] == "3" and f"FIXTURE IMPORT OK files={len(entries)}" in text,
                        f"Clang import {index} failed")
                _, nodes, found = read_image(image)
                for entry in detail["files"]:
                    actual = found[entry["path"]]
                    require(len(actual) == entry["result_bytes"] and sha(actual) == entry["result_sha256"],
                            f"Clang import {index} result differs at {entry['path']}")
                    if entry["path"].endswith("/cc1-fe-o0") and step == 3:
                        last_cc1 = {"boot": index, "prefix_bytes": entry["prefix_bytes"],
                                    "chunk_bytes": entry["chunk_bytes"], "seconds": record["seconds"],
                                    "host_limit_seconds": 600, "margin_seconds": 600 - record["seconds"],
                                    "result_sha256": entry["result_sha256"]}
                require(not any(em.reserved_import_path(p) for p in nodes), f"Clang import {index} leaked temp")
                save(f"CLANG_BOOT_{index}_OF_{len(plan)}")
            selected, nodes, found = read_image(image)
            require(found == dict(files), "full Clang opaque fixture differs from exact input set")
            expected_paths = {path.rstrip("/") for path, _ in files}
            for path in list(expected_paths):
                expected_paths.update(str(parent) for parent in pathlib.PurePosixPath(path).parents if str(parent) != "/")
            require(set(nodes) == expected_paths, "full Clang namespace contains unlisted objects")
            used_blocks = len({block for node in nodes.values() for block in node["blocks"]})
            free_bytes = (selected["geometry"]["data_blocks"] - used_blocks) * fs.BLOCK
            require(free_bytes >= manifest["headroom"], "Clang post-import headroom was consumed")
            require(last_cc1 is not None and last_cc1["result_sha256"] ==
                    "b328a121f6796fb326dc855628a3cb5a7ecd3a95c7c53930eb1610c91326e22c", "real cc1-fe final append")
            result["clang"] = {"files": len(files), "import_boots": len(plan), "total_seconds": time.monotonic() - begin,
                "last_cc1_append": last_cc1, "historical_approximation_seconds": 87 * 15,
                "peak_bytes": em.import_peak_bytes(files), "image_bytes": size, "post_import_free_bytes": free_bytes,
                "bundle_sha256": sha(pathlib.Path(args.clang_bundle).read_bytes()), "claim": "file import only"}
            with (image.parent / "CASE.json").open("x") as output:
                json.dump({"verdict": "PASS", "clang": result["clang"],
                           "observed_file_digests": {p: sha(data) for p, data in found.items()}}, output, indent=2)
                output.write("\n")
            result["cases"].append({"name": "full-real-clang-fixture-import", "verdict": "PASS"})
            (image.parent / "IMAGE-RECEIPT.json").write_text(json.dumps({"sha256": sha(image.read_bytes()),
                "disposition": "exact input bundle and raw boot results retained; mutable disk replay not required"}) + "\n")
            image.unlink()
        result["verdict"] = "PASS"
    except BaseException as error:
        result.update(verdict="FAIL", error=repr(error), traceback=traceback.format_exc(),
                      retained_images=[str(p) for p in (work / "images").rglob("*.img")],
                      image_custody="Retain failed-state images until halted state and diagnosis/replay custody are reconciled; no age/name-based disposal.")
    result["seconds"] = time.monotonic() - started
    (work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    records = {str(p.relative_to(work)): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
               for p in work.rglob("*") if p.is_file() and p.suffix not in (".img", ".bin")}
    (work / "COMPLETE.json").write_text(json.dumps({"verdict": result["verdict"], "source": result["source"],
                                                  "records": records}, indent=2) + "\n")
    print(f"FIXTURE IMPORT MATRIX {result['verdict']} cases={len(result['cases'])} boots={len(result['boots'])}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
