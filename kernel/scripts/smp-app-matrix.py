#!/usr/bin/env python3
"""Run sealed native ABSD applications with ordinary AP pressure enabled.

The application binaries and text fixtures come from a caller-owned sealed
copy.  Kernel builds, ISOs, VM logs, and filesystem images stay below --work;
the reusable Cargo target tree is supplied separately with --target.

Multicore pressure accepts long text-stats and custodied wc/sha256sum command
cases.  Command cases retain exact output checking and require task-specific
AP timer-preemption evidence from the pressure oracle.
"""

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace


# The sealed stable file-server executable is built with this release ID.
# Keep the VERSION fixture tied to the server artifact rather than the host
# environment's default (the ordinary native app suite uses `dev`).
FSD_RELEASE_ID = "absd-20261002.3"
COMMAND_APP_NAMES = ("wc", "sha256sum")


def require(ok, message):
    if not ok:
        raise SystemExit(f"SMP APP MATRIX FAILED: {message}")


def load_module(name, path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Campaign:
    def __init__(self, args):
        self.kernel = Path(__file__).resolve().parent.parent
        self.platform = args.platform.resolve()
        self.inputs = args.inputs.resolve()
        self.work = args.work.resolve()
        self.target = args.target.resolve()
        self.ap_native = args.ap_native
        self.multicore_pressure = args.multicore_pressure
        self.bsp_pressure = args.bsp_pressure
        self.cpus = args.cpus
        self.app_cpu = args.app_cpu
        self.long_text = args.long_text
        self.cases = args.cases
        self.command_inputs = args.command_inputs.resolve() if args.command_inputs else None
        require(self.kernel != Path("/data/git/absd-kernel"), "canonical kernel checkout")
        require(not self.work.exists(), f"work path already exists: {self.work}")
        self.work.mkdir(parents=True)
        self.target.mkdir(parents=True, exist_ok=True)
        self.qemu_helper = self.kernel / "scripts/smp-user-qemu.py"
        self.output_checker = self.kernel / "scripts/check-external-output.py"
        self.pressure_checker = self.kernel / "scripts/check-smp-app-pressure.py"
        require(self.qemu_helper.is_file(), f"missing QMP runner: {self.qemu_helper}")
        require(self.output_checker.is_file(), f"missing output checker: {self.output_checker}")
        require(self.pressure_checker.is_file(), f"missing multicore pressure oracle: {self.pressure_checker}")
        default_feature = "smp-scheduler-test" if (self.multicore_pressure or self.bsp_pressure) else "smp-user-test"
        self.build_feature = os.environ.get("SMP_BUILD_FEATURE", default_feature)
        require(self.build_feature in ("smp-user-test", "smp-scheduler-test"),
                "unknown SMP build feature")
        require(not (self.multicore_pressure or self.bsp_pressure) or self.build_feature == "smp-scheduler-test",
                "multicore pressure requires the smp-scheduler-test build feature")
        self.cargo = shutil.which("cargo") or "cargo"
        self.grub_mkrescue = shutil.which("grub-mkrescue") or "grub-mkrescue"
        self.inputs_copy = self.work / "inputs"
        self.input_hashes = {}
        self.boot_count = 0
        self.build_count = 0
        self._stage_inputs()
        if self.command_inputs is not None:
            self._stage_command_inputs()
        if self.long_text:
            self._stage_long_text()
        if set(self.cases) & set(COMMAND_APP_NAMES):
            self._stage_command_expected()
        (self.work / "input-manifest.sha256").write_text(
            "".join(f"{value}  {name}\n" for name, value in sorted(self.input_hashes.items()))
        )

    def _stage_inputs(self):
        files = [
            "probe.elf", "input.txt", "expected.txt",
            "text-stats.elf", "text-stats-input.txt", "text-stats-expected.txt",
            "exec-probe.elf", "fixture-import.elf", "exec-expected.txt",
            "sh-launch.elf", "sh-input.txt", "sh-expected.txt",
            "absd-fsd.elf",
            "commands/uname", "commands/echo", "commands/pwd", "commands/ls",
            "commands/cat", "commands/printenv", "commands/absd-sh", "commands/sh-probe",
            "commands/release",
        ]
        self.inputs_copy.mkdir()
        for name in files:
            source = self.inputs / name
            require(source.is_file(), f"sealed input is missing: {source}")
            data = source.read_bytes()
            if name.endswith(".elf") or name.startswith("commands/"):
                require(data.startswith(b"\x7fELF\x02"), f"input is not ELF64: {name}")
            destination = self.inputs_copy / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            self.input_hashes[name] = digest(data)

    def _stage_command_inputs(self):
        manifest_path = self.command_inputs / "inputs.sha256"
        require(manifest_path.is_file(), f"command input digest manifest is missing: {manifest_path}")
        manifest = {}
        for line in manifest_path.read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (commands/(?:wc|sha256sum))", line)
            require(match is not None, f"unexpected command input manifest row: {line!r}")
            digest_value, name = match.groups()
            require(name not in manifest, f"duplicate command input manifest row: {name}")
            manifest[name] = digest_value
        require(set(manifest) == {f"commands/{name}" for name in COMMAND_APP_NAMES},
                "command input digest manifest does not name exactly wc and sha256sum")
        for name in COMMAND_APP_NAMES:
            relative = f"commands/{name}"
            source = self.command_inputs / relative
            require(source.is_file() and not source.is_symlink(),
                    f"sealed command input is missing or is a symlink: {source}")
            data = source.read_bytes()
            require(data.startswith(b"\x7fELF\x02"), f"command input is not ELF64: {relative}")
            actual = digest(data)
            require(actual == manifest[relative], f"command input hash differs from custody manifest: {relative}")
            destination = self.inputs_copy / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            self.input_hashes[relative] = actual

    def _stage_command_expected(self):
        source = (self.inputs_copy / "text-stats-input.txt").read_bytes()
        require(len(source) == 34 and source.endswith(b"\n") and source.count(b"\n") == 1,
                "sealed command input line is not exactly 34 bytes including one LF")
        if self.long_text:
            data = (self.inputs_copy / "text-stats-long-input.txt").read_bytes()
            require(data == source * 32768,
                    "long command input differs from the sealed 32768-line corpus")
        else:
            data = source
        lines = data.count(b"\n")
        words = 0
        in_word = False
        whitespace = b" \t\n\r\v\f"
        for byte in data:
            if byte in whitespace:
                in_word = False
            elif not in_word:
                words += 1
                in_word = True
        width = max(len(str(lines)), len(str(words)), len(str(len(data))))
        wc_expected = " ".join(f"{value:>{width}}" for value in (lines, words, len(data))) + "\n"
        sha_expected = f"{digest(data)}  -\n"
        for name, expected in (("wc-expected.txt", wc_expected.encode()),
                               ("sha256sum-expected.txt", sha_expected.encode())):
            path = self.inputs_copy / name
            path.write_bytes(expected)
            self.input_hashes[name] = digest(expected)

    def _stage_long_text(self):
        source = (self.inputs_copy / "text-stats-input.txt").read_bytes()
        require(len(source) == 34 and source.endswith(b"\n") and source.count(b"\n") == 1,
                "sealed text-stats line is not exactly 34 bytes including one LF")
        repetitions = 32768
        input_data = source * repetitions
        require(len(input_data) == 34 * repetitions
                and input_data.count(b"\n") == repetitions,
                "generated long text input has incorrect byte/line count")
        expected_data = (
            f"bytes={34 * repetitions} lines={repetitions} "
            f"words={6 * repetitions} unique=3\n"
            f"alpha={3 * repetitions}\n"
            f"beta={2 * repetitions}\n"
            f"gamma={repetitions}\n"
            "ABSD RUST TEXT STATS OK\n"
        ).encode()
        for name, data in (("text-stats-long-input.txt", input_data),
                           ("text-stats-long-expected.txt", expected_data)):
            path = self.inputs_copy / name
            path.write_bytes(data)
            self.input_hashes[name] = digest(data)

    def build(self, worker, input_bytes, out, file_server=None):
        input_path = out / "external-input.bin"
        input_path.write_bytes(input_bytes)
        env = os.environ.copy()
        env.update({
            "ABSD_EXTERNAL_USER_ELF": str(Path(worker).resolve()),
            "ABSD_EXTERNAL_INPUT": str(input_path.resolve()),
            "ABSD_EXTERNAL_READER_ELF": "",
            "ABSD_EXTERNAL_READER_INPUT": "",
            "ABSD_BROKER_POLICY": "",
            "ABSD_FILE_SERVER_ELF": str(Path(file_server).resolve()) if file_server else "",
            "ABSD_NET_WAIT_TICKS": "",
            "CARGO_TARGET_DIR": str(self.target),
        })
        for index in range(1, 5):
            env[f"ABSD_OWNER_{index}_ELF"] = ""
        log_path = out / "cargo.log"
        feature = self.build_feature
        command = [self.cargo, "rustc", "--offline", "--features", feature,
                   "--target-dir", str(self.target), "--bin", "absd-kernel", "--",
                   "-C", "relocation-model=static", "-C", "code-model=kernel",
                   "-C", "no-redzone=yes", "-C", "link-arg=-Tlinker.ld",
                   "-C", "link-arg=-nostdlib", "-C", "link-arg=-no-pie"]
        self.build_count += 1
        with log_path.open("wb") as log:
            result = subprocess.run(command, cwd=self.kernel, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, check=False)
        require(result.returncode == 0, f"kernel build {self.build_count} failed; see {log_path}")
        kernel_elf = self.target / "debug/absd-kernel"
        require(kernel_elf.is_file(), f"kernel output missing: {kernel_elf}")
        staged = out / "absd-kernel"
        shutil.copyfile(kernel_elf, staged)
        (out / "kernel.sha256").write_text(f"{digest(staged.read_bytes())}  absd-kernel\n")
        return staged

    def iso(self, worker, input_bytes, out, grub_line, file_server=None):
        if self.bsp_pressure:
            grub_line += " smp-multicore-pressure smp-bsp-app"
            if self.cpus != 2:
                grub_line += f" smp-cpus={self.cpus}"
            mode = "durable" if grub_line.startswith("durable=") else "external"
            (out / "bsp-pressure-mode").write_text(mode + "\n")
        if self.build_feature == "smp-scheduler-test":
            grub_line += " smp-scheduler-test"
        kernel_elf = self.build(worker, input_bytes, out, file_server)
        iso_root = out / "iso"
        grub_dir = iso_root / "boot/grub"
        grub_dir.mkdir(parents=True)
        shutil.copyfile(kernel_elf, iso_root / "boot/absd-kernel")
        (grub_dir / "grub.cfg").write_text(
            "set timeout=0\nmenuentry \"ABSD SMP application qualification\" {\n"
            f"  multiboot2 /boot/absd-kernel {grub_line}\n  boot\n}}\n"
        )
        image = out / "boot.iso"
        with (out / "grub-mkrescue.log").open("wb") as log:
            result = subprocess.run([self.grub_mkrescue, "-o", str(image), str(iso_root)],
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        require(result.returncode == 0 and image.is_file(), f"ISO creation failed in {out}")
        return image

    def qemu(self, out, extra=()):
        self.boot_count += 1
        command = [sys.executable, str(self.qemu_helper), str(out), *map(str, extra)]
        runner_env = os.environ.copy()
        if self.multicore_pressure or self.bsp_pressure:
            runner_env["SMP_BENCH_VCPUS"] = str(self.cpus)
            runner_env["SMP_TOPOLOGY"] = "separate"
        with (out / "runner.log").open("wb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    env=runner_env, check=False)
        status_path = out / "qemu.status"
        require(status_path.is_file(), f"QMP runner did not write status in {out}")
        status = int(status_path.read_text().strip())
        require(result.returncode == 3 and status == 3,
                f"QEMU status {status} / runner status {result.returncode} in {out}")
        serial = (out / "serial.log").read_bytes()
        lines = serial.decode(errors="replace").splitlines()
        require(not any(re.search(r"ABSD PANIC:|KERNEL FAULT|FAILED", line) for line in lines),
                f"failure record in {out}/serial.log")
        pressure = [line for line in lines if line.startswith("SMP USER PRESSURE ")]
        require(len(pressure) == 1, f"expected one AP pressure record in {out}: {pressure}")
        pressure_fields = {key: int(value) for key, value in
                           re.findall(r"([a-z0-9-]+)=([0-9]+)", pressure[0])}
        require(pressure_fields.get("calls1", 0) > 0,
                f"AP ring-3 syscall progress missing in {out}: {pressure[0]}")
        timer = [line for line in lines if line.startswith("SMP TIMER SUMMARY cpu=1 ")]
        require(len(timer) == 1, f"expected one AP timer summary in {out}: {timer}")
        timer_fields = {key: int(value) for key, value in
                        re.findall(r"([a-z0-9-]+)=([0-9]+)", timer[0])}
        require(timer_fields.get("user-irqs", 0) > 0 and timer_fields.get("switches1", 0) > 0,
                f"AP user timer preemption missing in {out}: {timer[0]}")
        require(lines.count("ABSD BOOT OK") <= 1,
                f"duplicate ABSD BOOT OK records in {out}/serial.log")
        if self.ap_native:
            traps = [line for line in lines if line.startswith('SMP APP TRAP ')]
            summaries = [line for line in lines if line.startswith('SMP APP SUMMARY ')]
            require(len(traps) == len(summaries) == 1, 'missing exact native AP witness')
            require(traps[0].endswith('cpl=3 cr3=owned catalog=external-workload'), 'invalid native AP trap')
            native = {k:int(v) for k,v in re.findall(r'([a-z0-9-]+)=(\d+)', summaries[0])}
            trap = {k:int(v) for k,v in re.findall(r'([a-z0-9-]+)=(\d+)', traps[0])}
            expected_cpu = self.app_cpu if self.multicore_pressure else 1
            require(native['cpu'] == trap['cpu'] == expected_cpu and native['pid'] == trap['pid'],
                    'native AP identity mismatch')
            require(native['calls'] > 0 and native['exited'] == native['departed'] == 1 and native['faults'] == 0, 'native lifecycle failure')
        if self.bsp_pressure:
            subprocess.run([sys.executable, str(self.kernel / "scripts/check-smp-bsp-pressure.py"),
                            "--serial", str(out / "serial.log"), "--cpus", str(self.cpus),
                            "--mode", (out / "bsp-pressure-mode").read_text().strip(),
                            "--placement", str(out / "vcpu-placement.json")], check=True)
        return serial

    def external_options(self):
        options = 'external smp-user-pressure smp-user-preempt'
        if self.multicore_pressure:
            options += f' smp-multicore-pressure smp-app-cpu={self.app_cpu}'
            if self.cpus != 2:
                options += f' smp-cpus={self.cpus}'
        return options + (' smp-ap-app' if self.ap_native else '')

    def standalone(self, name, worker, input_path, expected_path, marker=None):
        out = self.work / name
        out.mkdir()
        input_bytes = input_path.read_bytes()
        self.iso(worker, input_bytes, out, self.external_options())
        serial = self.qemu(out)
        require(re.search(rb"^EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0$",
                          serial, re.M), f"{name}: external accounting line missing")
        require(b"EXTERNAL WORKLOAD OK\n" in serial and b"ABSD BOOT OK\n" in serial,
                f"{name}: orderly external completion missing")
        subprocess.run([sys.executable, str(self.output_checker), str(out / "serial.log"),
                        str(expected_path)], check=True)
        if self.multicore_pressure:
            subprocess.run([sys.executable, str(self.pressure_checker), str(out / "serial.log"),
                            "--cpus", str(self.cpus), "--app-cpu", str(self.app_cpu),
                            "--placement", str(out / "vcpu-placement.json")], check=True)
        if marker is not None:
            require(marker.encode() + b"\n" in expected_path.read_bytes(),
                    f"{name}: sealed expected output does not contain marker {marker}")
            print(f"SMP APP EXTERNAL OK case={name} pressure=1 preempt=1")
        elif self.multicore_pressure:
            print(f"SMP APP EXTERNAL OK case={name} scope=native-cpl3-syscall-exit "
                  "timer=native-task-preempted")
        else:
            print(f"SMP APP EXTERNAL OK case={name} scope=native-cpl3-syscall-exit "
                  "timer=aggregate-ap-only")

    def run_matrix(self, kind):
        platform_scripts = self.platform / "scripts"
        exec_mod = load_module("smp_app_exec_matrix", platform_scripts / "exec-matrix.py")
        sh_mod = load_module("smp_app_sh_matrix", platform_scripts / "sh-matrix.py")
        if kind == "exec":
            base = exec_mod.Matrix
            label = "exec"
        else:
            base = sh_mod.Matrix
            label = "sh"
        campaign = self

        class PressureMatrix(base):
            def boot(self, name, step, image, input_bytes, worker):
                self.boots += 1
                out = campaign.work / f"{label}-{name}-{campaign.boot_count:03d}"
                out.mkdir()
                campaign.iso(worker, input_bytes, out,
                             f"durable={step} smp-user-pressure smp-user-preempt")
                drive = ["-drive", f"file={Path(image).resolve()},format=raw,if=ide,index=0"]
                serial = campaign.qemu(out, drive)
                captured = exec_mod.dm.Harness.captured(serial)
                return 3, serial, captured

        copied = self.inputs_copy
        args = SimpleNamespace(
            kernel=str(self.kernel), importer=str(copied / "fixture-import.elf"),
            probe=str(copied / ("exec-probe.elf" if kind == "exec" else "sh-launch.elf")),
            commands=str(copied / "commands"),
            expected=str(copied / ("exec-expected.txt" if kind == "exec" else "sh-expected.txt")),
            work=str(self.work / f"{kind}-matrix-work"), qemu="",
        )
        if kind == "sh":
            args.shell = str(copied / "commands/absd-sh")
            args.input = str(copied / "sh-input.txt")
            args.launcher = str(copied / "sh-launch.elf")
        # The live platform oracle normalizes uname's explicitly configured
        # build ID before its exact stream comparison. These copied commands
        # are release artifacts, not builds with the host's default `dev` ID.
        require(FSD_RELEASE_ID.encode() in (copied / "commands/uname").read_bytes(),
                "sealed uname does not identify the pinned release")
        matrix = PressureMatrix(args)
        previous_release = os.environ.get("ABSD_RELEASE_ID")
        os.environ["ABSD_RELEASE_ID"] = FSD_RELEASE_ID
        try:
            matrix.run()
        finally:
            if previous_release is None:
                os.environ.pop("ABSD_RELEASE_ID", None)
            else:
                os.environ["ABSD_RELEASE_ID"] = previous_release
        print(f"SMP APP MATRIX OK case={kind} pressure=1 preempt=1 boots={matrix.boots}")

    def run_fsd_release(self):
        platform_scripts = self.platform / "scripts"
        exec_mod = load_module("smp_app_fsd_exec_matrix", platform_scripts / "exec-matrix.py")
        release_record = load_module("smp_app_release_record", platform_scripts / "release_record.py")
        copied = self.inputs_copy
        fsd_work = self.work / "release-matrix-work"
        fsd_work.mkdir(mode=0o700)
        fsd_work.chmod(0o700)
        image = fsd_work / "fsd.img"
        with image.open("wb") as handle:
            handle.truncate(exec_mod.IMAGE_BYTES)
        image.chmod(0o600)
        require(image.stat().st_size == 16 * 1024 * 1024, "FSD fixture image is not 16 MiB")
        require((image.stat().st_mode & 0o777) == 0o600
                and (fsd_work.stat().st_mode & 0o777) == 0o700,
                "FSD seed custody permissions are not private")

        release_id = FSD_RELEASE_ID
        release_record.check_id(release_id)
        fsd_elf = (copied / "absd-fsd.elf").read_bytes()
        require(fsd_elf.startswith(b"\x7fELF\x02"), "file server is not ELF64")
        require(release_id.encode() in fsd_elf,
                f"sealed file server does not identify release {release_id}")
        release_elf = (copied / "commands/release").read_bytes()
        require(release_elf.startswith(b"\x7fELF\x02"), "release command is not ELF64")
        files = release_record.release_layout([("/bin/release", release_elf)], release_id)
        import_args = SimpleNamespace(
            kernel=str(self.kernel), importer=str(copied / "fixture-import.elf"),
            probe=str(copied / "exec-probe.elf"), commands=str(copied / "commands"),
            expected=str(copied / "exec-expected.txt"), work=str(fsd_work / "import-work"), qemu="",
        )
        campaign = self

        class ImportMatrix(exec_mod.Matrix):
            def boot(self, name, step, target_image, input_bytes, worker):
                self.boots += 1
                out = fsd_work / f"import-{step}-{self.boots:03d}"
                out.mkdir()
                campaign.iso(worker, input_bytes, out,
                             f"durable={step} smp-user-pressure smp-user-preempt")
                drive = ["-drive", f"file={Path(target_image).resolve()},format=raw,if=ide,index=0"]
                serial = campaign.qemu(out, drive)
                return 3, serial, exec_mod.dm.Harness.captured(serial)

        importer = ImportMatrix(import_args)
        importer.install(image, files)

        lifecycle = {
            "schema_version": 1,
            "owner": "root",
            "custodian_agent": "/root",
            "owner_uid": image.stat().st_uid,
            "owner_gid": image.stat().st_gid,
            "image_mode": "0600",
            "directory_mode": "0700",
            "campaign": "ABSD native AP userspace pressure",
            "case": "FSD release VERSION client/server",
            "purpose": "mandatory local absd-fsd bootstrap creates its host-key seed",
            "authorized_destinations": [],
            "creation_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "intended_lifetime": "this qualification case and its receipt",
            "custody_path": str(image),
            "host_seed_path": "/ssh/host_ed25519_seed",
            "ssh_listener": "none",
            "ssh_enrollment": "none",
            "ssh_agent_use": "none",
            "remote_use": "none",
            "retirement_condition": "closeout after receipt and primary campaign checks",
            "recovery_dependency_on_seed": "none",
            "seed_state": "not-yet-generated",
            "boot_state": "not-started",
        }
        lifecycle_path = fsd_work / "host-seed-lifecycle.json"
        lifecycle_tmp = lifecycle_path.with_suffix(".json.tmp")

        def write_lifecycle():
            lifecycle_tmp.write_text(json.dumps(lifecycle, indent=2) + "\n")
            lifecycle_tmp.chmod(0o600)
            os.replace(lifecycle_tmp, lifecycle_path)

        write_lifecycle()

        out = fsd_work / "release-boot"
        out.mkdir(mode=0o700)
        out.chmod(0o700)
        expected = out / "release.expected.txt"
        expected.write_text(
            f"release={release_id} kernel_abi=1 fsd_protocol=2 fs_format=2 app_abi=1\n"
        )
        self.iso(copied / "commands/release", b"", out,
                 "durable=4 fsd smp-user-pressure smp-user-preempt",
                 file_server=copied / "absd-fsd.elf")
        try:
            lifecycle["boot_state"] = "generation-pending"
            write_lifecycle()
            serial = self.qemu(out, ["-drive", f"file={image},format=raw,if=ide,index=0"])
            subprocess.run([sys.executable, str(self.output_checker), str(out / "serial.log"),
                            str(expected)], check=True)
            lines = serial.decode(errors="replace").splitlines()
            require(lines.count(f"RELEASE OK release={release_id}") == 1,
                    "native file server did not validate the selected release")
            require(sum(bool(re.fullmatch(
                r"FSD READY channels=11 slots=10 fs_seq=\d+ formatted=(?:true|false) fs_objects=\d+", line))
                for line in lines) == 1, "file server did not report its ready boundary")
            starts = [re.fullmatch(r"FILE SERVER START pid=(\d+) channels=(\d+)", line)
                      for line in lines if line.startswith("FILE SERVER START ")]
            outcomes = [re.fullmatch(r"FILE SERVER OUTCOME pid=(\d+) status=0", line)
                        for line in lines if line.startswith("FILE SERVER OUTCOME ")]
            require(len(starts) == len(outcomes) == 1 and starts[0] and outcomes[0]
                    and starts[0].group(1) == outcomes[0].group(1),
                    "file-server start/clean-stop lifecycle mismatch")
            require(starts[0].group(2) == "11", "unexpected FSD channel count")
            accounting = [line for line in lines if line.startswith("DURABLE status=")]
            require(len(accounting) == 1 and re.fullmatch(
                r"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0(?: [a-z0-9_]+=[0-9]+)*",
                accounting[0]), f"nonzero durable accounting: {accounting}")
            require(lines.count("DURABLE WORKLOAD OK") == 1 and lines.count("ABSD BOOT OK") == 1,
                    "FSD release boot did not finish exactly once")
            require(lines.count("FSD HOST KEY GENERATED path=/ssh/host_ed25519_seed") == 1,
                    "expected FSD's one local host-seed creation")

            sys.path.insert(0, str(platform_scripts))
            try:
                ssh_absd = load_module("smp_app_ssh_absd_key_reader", platform_scripts / "ssh_absd.py")
                target = ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget)
                target.image = image
                public = target.host_public_from_image()
            finally:
                sys.path.remove(str(platform_scripts))
            key_type, encoded_key = public.split()
            require(key_type == "ssh-ed25519", "FSD seed did not derive an Ed25519 host public key")
            public_blob = base64.b64decode(encoded_key, validate=True)
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip("=")
            lifecycle["seed_state"] = "generated-local-only"
            lifecycle["boot_state"] = "passed"
            lifecycle["public_fingerprint"] = fingerprint
            lifecycle["disposition"] = "retain only inside the private campaign image until closeout"
            write_lifecycle()
        except BaseException:
            lifecycle["seed_state"] = "generation-or-outcome-indeterminate"
            lifecycle["boot_state"] = "failed-or-incomplete"
            lifecycle["disposition"] = "retain private image for owner reconciliation at closeout"
            write_lifecycle()
            raise
        print(f"SMP APP FSD RELEASE OK release={release_id} fingerprint={fingerprint} "
              "seed-custody=private-image listener=none")

    def run(self, cases):
        copied = self.inputs_copy
        if "probe" in cases:
            self.standalone("probe", copied / "probe.elf", copied / "input.txt",
                            copied / "expected.txt", "ABSD STD PROBE OK")
        if "text-stats" in cases:
            text_input = copied / ("text-stats-long-input.txt" if self.long_text
                                   else "text-stats-input.txt")
            text_expected = copied / ("text-stats-long-expected.txt" if self.long_text
                                      else "text-stats-expected.txt")
            case_name = "text-stats-multicore-pressure" if self.multicore_pressure else "text-stats"
            self.standalone(case_name, copied / "text-stats.elf",
                            text_input, text_expected,
                            "ABSD RUST TEXT STATS OK")
        if "wc" in cases:
            command_input = copied / ("text-stats-long-input.txt" if self.long_text
                                      else "text-stats-input.txt")
            self.standalone("wc", copied / "commands/wc",
                            command_input,
                            copied / "wc-expected.txt")
        if "sha256sum" in cases:
            command_input = copied / ("text-stats-long-input.txt" if self.long_text
                                      else "text-stats-input.txt")
            self.standalone("sha256sum", copied / "commands/sha256sum",
                            command_input,
                            copied / "sha256sum-expected.txt")
        if "uname" in cases:
            out = self.work / "uname"
            out.mkdir()
            expected = out / "uname.expected.txt"
            expected.write_bytes(b"ABSD\n")
            self.iso(copied / "commands/uname", b"", out,
                     self.external_options())
            serial = self.qemu(out)
            require(re.search(rb"^EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0$",
                              serial, re.M), "uname: external accounting line missing")
            require(b"EXTERNAL WORKLOAD OK\n" in serial and b"ABSD BOOT OK\n" in serial,
                    "uname: orderly external completion missing")
            subprocess.run([sys.executable, str(self.output_checker), str(out / "serial.log"),
                            str(expected)], check=True)
            print("SMP APP EXTERNAL OK case=uname pressure=1 preempt=1")
        if "release" in cases:
            self.run_fsd_release()
        if "exec" in cases:
            self.run_matrix("exec")
        if "sh" in cases:
            self.run_matrix("sh")
        mode = " multicore-pressure=1" if self.multicore_pressure else " bsp-pressure=1" if self.bsp_pressure else ""
        print(f"SMP APP MATRIX COMPLETE cases={','.join(cases)} builds={self.build_count} "
              f"boots={self.boot_count}{mode}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, required=True,
                        help="read-only platform checkout used for exact matrix oracles")
    parser.add_argument("--inputs", type=Path, required=True,
                        help="sealed copied ELFs and fixtures; never read from platform build outputs")
    parser.add_argument("--work", type=Path, required=True,
                        help="new campaign-owned output directory on the admitted bulk filesystem")
    parser.add_argument("--target", type=Path, required=True,
                        help="campaign-owned Cargo target directory on the admitted bulk filesystem")
    parser.add_argument("--cases", nargs="+",
                        choices=["probe", "text-stats", "uname", "exec", "sh", "release",
                                 "wc", "sha256sum"])
    parser.add_argument('--ap-native', action='store_true', help='closed embedded external worker on CPU1')
    parser.add_argument('--command-inputs', type=Path,
                        help='custodied wc/sha256sum ELFs required when either command case is selected')
    parser.add_argument('--multicore-pressure', action='store_true',
                        help='pin an admitted native workload on one AP with pressure on every AP')
    parser.add_argument('--bsp-pressure', action='store_true',
                        help='retain application placement on CPU0 with fixed preempted pressure on every AP')
    parser.add_argument('--cpus', type=int, choices=(2, 4, 6),
                        help='explicit multicore-pressure guest CPU count')
    parser.add_argument('--app-cpu', type=int, choices=(1, 2, 3, 4, 5),
                        help='AP placement for the native workload')
    parser.add_argument('--long-text', action='store_true',
                        help='repeat the sealed 34-byte text-stats line 32768 times')
    args = parser.parse_args()
    require(not args.bsp_pressure or (not args.multicore_pressure and not args.ap_native
                                     and args.app_cpu is None and not args.long_text
                                     and args.command_inputs is None),
            'BSP pressure is exclusive with AP application modes and placement')
    if args.bsp_pressure:
        require(args.cpus is not None, 'BSP pressure requires --cpus')
        args.cases = args.cases or ['probe', 'text-stats', 'uname', 'exec', 'sh']
        require(set(args.cases) <= {'probe', 'text-stats', 'uname', 'exec', 'sh', 'release'},
                'BSP pressure requires existing ordinary application cases')
    elif args.multicore_pressure:
        require(args.cpus is not None and args.app_cpu is not None,
                'multicore pressure requires --cpus and --app-cpu')
        require(args.app_cpu < args.cpus,
                'selected native application CPU must be an admitted AP')
        require(args.long_text, 'multicore pressure requires --long-text')
        if args.cases is None:
            args.cases = ['text-stats']
        require(len(args.cases) == len(set(args.cases)),
                'multicore pressure cases must be unique')
        require(set(args.cases) <= {'text-stats', *COMMAND_APP_NAMES},
                'multicore pressure admits only text-stats, wc, and sha256sum')
        args.ap_native = True
    else:
        require(args.cpus is None and args.app_cpu is None and not args.long_text,
                '--cpus, --app-cpu, and --long-text require --multicore-pressure')
        args.cases = args.cases or ['probe', 'text-stats', 'uname', 'exec', 'sh']
    command_cases = set(args.cases) & set(COMMAND_APP_NAMES)
    require(not command_cases or args.ap_native,
            'wc and sha256sum cases require AP-native mode')
    require((args.command_inputs is not None) == bool(command_cases),
            '--command-inputs is required exactly when wc or sha256sum is selected')
    require(not args.ap_native or set(args.cases) <= {'probe','text-stats','uname', *COMMAND_APP_NAMES},
            'AP native admission is restricted to standalone cases')
    Campaign(args).run(args.cases)


if __name__ == "__main__":
    main()
