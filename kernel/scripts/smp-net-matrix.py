#!/usr/bin/env python3
"""Run the sealed native netd matrix with KVM AP userspace pressure.

The platform's net-matrix.py remains the authority for frame and TCP
protocol oracles.  This wrapper supplies a feature-enabled kernel build,
KVM/QMP vCPU pinning, and per-boot AP progress checks around those oracles.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import shutil
import socket
import subprocess
import sys
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(f"SMP NET MATRIX FAILED: {message}")


def load_net_matrix(path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("smp_net_platform_matrix", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Producer:
    def __init__(self, kernel, inputs, work, target, baseline_up=False,
                 cpus=2, build_feature=None):
        self.kernel = kernel.resolve()
        self.inputs = inputs.resolve()
        self.work = work.resolve()
        self.target = target.resolve()
        self.started = time.monotonic()
        self.baseline_up = baseline_up
        self.cpus = cpus
        self.build_feature = build_feature or os.environ.get("SMP_BUILD_FEATURE", "smp-user-test")
        self.bsp_pressure = self.cpus in (4, 6)
        self.platform_script = self.inputs / "scripts/net-matrix.py"
        self.elf = self.inputs / "netd-probe.elf"
        self.policy = self.inputs / "broker-policy.txt"
        self.broker_echo = self.inputs / "broker-echo.elf"
        self.target.mkdir(parents=True, exist_ok=True)
        require(self.platform_script.is_file(), f"missing sealed net matrix: {self.platform_script}")
        for path in (self.elf, self.policy, self.broker_echo):
            require(path.is_file(), f"missing sealed network fixture: {path}")
        require(self.elf.read_bytes().startswith(b"\x7fELF\x02"), "netd-probe is not ELF64")
        require(self.broker_echo.read_bytes().startswith(b"\x7fELF\x02"), "broker-echo is not ELF64")
        self.hashes = {}
        for path in (self.platform_script, self.elf, self.policy, self.broker_echo):
            self.hashes[str(path.relative_to(self.inputs))] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.work / "input-manifest.sha256").write_text(
            "".join(f"{value}  {name}\n" for name, value in sorted(self.hashes.items()))
        )
        self.qemu_receipts = {}
        self.active_qemu = set()
        self.build_count = 0
        self.boot_records = []
        self.phase_records = []
        self.matrix = load_net_matrix(self.platform_script)
        self._install_hooks()

    def _build_iso(self, kernel, elf, work, step, broker=()):
        require(Path(kernel).resolve() == self.kernel, "matrix requested an unexpected kernel path")
        require(Path(elf).resolve() == self.elf, "matrix requested an unexpected network ELF")
        out = self.work / f"build-step-{step}"
        out.mkdir()
        empty_input = out / "external-input.bin"
        empty_input.write_bytes(b"")
        make_args = {}
        for item in broker:
            if "=" in item:
                key, value = item.split("=", 1)
                make_args[key] = value
        env = os.environ.copy()
        env.update({
            "ABSD_EXTERNAL_USER_ELF": str(self.elf),
            "ABSD_EXTERNAL_INPUT": str(empty_input),
            "ABSD_EXTERNAL_READER_ELF": "",
            "ABSD_EXTERNAL_READER_INPUT": "",
            "ABSD_FILE_SERVER_ELF": "",
            "ABSD_NET_WAIT_TICKS": "",
            "ABSD_BROKER_POLICY": make_args.get("BROKER_POLICY", ""),
            "ABSD_OWNER_1_ELF": make_args.get("OWNER_1_ELF", ""),
            "ABSD_OWNER_2_ELF": "",
            "ABSD_OWNER_3_ELF": "",
            "ABSD_OWNER_4_ELF": "",
            "CARGO_TARGET_DIR": str(self.target),
        })
        log_path = out / "cargo.log"
        feature = self.build_feature
        require(feature in ("smp-user-test", "smp-scheduler-test"), "unknown SMP build feature")
        require(not self.bsp_pressure or feature == "smp-scheduler-test",
                "4/6-vCPU network pressure requires smp-scheduler-test")
        command = [shutil.which("cargo") or "cargo", "rustc", "--offline", "--features",
                   feature, "--target-dir", str(self.target), "--bin", "absd-kernel", "--",
                   "-C", "relocation-model=static", "-C", "code-model=kernel",
                   "-C", "no-redzone=yes", "-C", "link-arg=-Tlinker.ld",
                   "-C", "link-arg=-nostdlib", "-C", "link-arg=-no-pie"]
        self.build_count += 1
        with log_path.open("wb") as log:
            result = subprocess.run(command, cwd=self.kernel, env=env,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        require(result.returncode == 0, f"kernel build failed for durable step {step}; see {log_path}")
        kernel_elf = self.target / "debug/absd-kernel"
        require(kernel_elf.is_file(), f"kernel ELF missing after step {step} build")
        iso_root = out / "iso"
        grub_dir = iso_root / "boot/grub"
        grub_dir.mkdir(parents=True)
        shutil.copyfile(kernel_elf, iso_root / "boot/absd-kernel")
        mode_options = "net" if self.baseline_up else "net smp-user-pressure smp-user-preempt"
        if self.build_feature == "smp-scheduler-test":
            require(not self.baseline_up,"modern scheduler network case requires two CPUs")
            mode_options += " smp-scheduler-test"
        if self.bsp_pressure:
            mode_options += f" smp-multicore-pressure smp-bsp-app smp-cpus={self.cpus}"
        menuentry = ("ABSD netd single-vCPU baseline" if self.baseline_up else
                     f"ABSD netd {self.cpus}-vCPU BSP pressure" if self.bsp_pressure else
                     "ABSD netd AP pressure")
        (grub_dir / "grub.cfg").write_text(
            f"set timeout=0\nmenuentry \"{menuentry}\" {{\n"
            f"  multiboot2 /boot/absd-kernel durable={step} {mode_options}\n"
            "  boot\n}\n"
        )
        iso = self.work / f"net-{step}.iso"
        with (out / "grub-mkrescue.log").open("wb") as log:
            built = subprocess.run([shutil.which("grub-mkrescue") or "grub-mkrescue", "-o",
                                    str(iso), str(iso_root)], stdout=log,
                                   stderr=subprocess.STDOUT, check=False)
        require(built.returncode == 0 and iso.is_file(), f"ISO creation failed for step {step}")
        image = self.work / f"net-{step}.img"
        with image.open("wb") as handle:
            handle.truncate(2 * 1024 * 1024)
        return str(iso), str(image)

    @staticmethod
    def _qmp_request(stream, name):
        stream.write((json.dumps({"execute": name}) + "\n").encode())
        stream.flush()
        while True:
            response = json.loads(stream.readline())
            if "return" in response:
                return response["return"]
            if "error" in response:
                raise RuntimeError(f"QMP {name} failed: {response['error']}")

    def _start_qemu(self, iso, image, log_path, netdev):
        log = Path(log_path)
        log.unlink(missing_ok=True)
        qmp_path = log.with_suffix(".qmp.sock")
        qmp_path.unlink(missing_ok=True)
        vcpu_count = self.cpus
        if self.bsp_pressure:
            guest_topology = {"sockets": 1, "cores": vcpu_count, "threads": 1}
            guest_smp = (f"{vcpu_count},sockets={guest_topology['sockets']},"
                         f"cores={guest_topology['cores']},threads={guest_topology['threads']}")
        else:
            guest_topology = None
            guest_smp = str(vcpu_count)
        command = [self.matrix.QEMU, "-accel", "kvm", "-cpu", "host", "-smp", guest_smp,
                   "-m", "256M", "-S", "-qmp", f"unix:{qmp_path},server=on,wait=off",
                   "-cdrom", str(iso), "-drive", f"file={image},format=raw,if=ide,index=0",
                   "-display", "none", "-serial", f"file:{log}", "-no-reboot", "-no-shutdown",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", "e1000,netdev=n0", *netdev]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.active_qemu.add(process)
        try:
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(5)
            for _ in range(100):
                try:
                    connection.connect(str(qmp_path))
                    break
                except FileNotFoundError:
                    if process.poll() is not None:
                        raise RuntimeError("QEMU exited before QMP readiness")
                    time.sleep(0.05)
            else:
                raise TimeoutError(f"QMP socket not ready: {qmp_path}")
            stream = connection.makefile("rwb")
            greeting = json.loads(stream.readline())
            self._qmp_request(stream, "qmp_capabilities")
            kvm = self._qmp_request(stream, "query-kvm")
            require(kvm == {"enabled": True, "present": True}, f"KVM unavailable: {kvm}")
            allowed = sorted(os.sched_getaffinity(0))
            topology = {}
            for cpu in allowed:
                base = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
                topology[cpu] = (int((base / "physical_package_id").read_text()),
                                 int((base / "core_id").read_text()))
            first = allowed[0]
            placement = [first]
            if self.bsp_pressure:
                seen_cores = {topology[first]}
                for cpu in allowed:
                    if cpu == first or topology[cpu] in seen_cores:
                        continue
                    placement.append(cpu)
                    seen_cores.add(topology[cpu])
                    if len(placement) == vcpu_count:
                        break
                require(len(placement) == vcpu_count,
                        f"not enough distinct host cores for {vcpu_count} vCPUs")
            elif vcpu_count == 2:
                second = next(cpu for cpu in allowed if topology[cpu] != topology[first])
                placement.append(second)
            vcpus = self._qmp_request(stream, "query-cpus-fast")
            require(len(vcpus) == vcpu_count,
                    f"expected {vcpu_count} QEMU vCPUs, saw {len(vcpus)}")
            require({entry.get("cpu-index") for entry in vcpus} == set(range(vcpu_count)),
                    f"QEMU vCPU indexes are incomplete or duplicated: {vcpus}")
            for entry in vcpus:
                assigned = placement[entry["cpu-index"]]
                os.sched_setaffinity(entry["thread-id"], {assigned})
                entry["host-cpu"] = assigned
                if self.bsp_pressure:
                    entry["host-package"], entry["host-core"] = topology[assigned]
                else:
                    entry["host-core"] = topology[assigned]
                entry["affinity"] = sorted(os.sched_getaffinity(entry["thread-id"] ))
                require(entry["affinity"] == [assigned], f"vCPU affinity mismatch: {entry}")
            self.qemu_receipts[process] = {
                "command": command, "qmp": greeting, "kvm": kvm, "vcpus": vcpus,
                "mode": ("baseline-up" if self.baseline_up else
                         f"bsp-pressure-{vcpu_count}" if self.bsp_pressure else "ap-pressure"),
                "started_monotonic": time.monotonic(),
                "children_usage_before": resource.getrusage(resource.RUSAGE_CHILDREN),
                "placement": str(log.with_suffix(".vcpu-placement.json")),
                "status": str(log.with_suffix(".qemu.status")),
            }
            receipt = self.qemu_receipts[process]
            placement_receipt = {"qemu_pid": process.pid, "qmp": greeting, "kvm": kvm,
                                 "mode": receipt["mode"], "vcpus": vcpus, "command": command}
            if self.bsp_pressure:
                placement_receipt.update({
                    "host_topology": "separate",
                    "guest_topology": guest_topology,
                    "guest_topology_mode": "explicit-smp-scheduler-test",
                })
            Path(receipt["placement"]).write_text(json.dumps(placement_receipt, indent=2) + "\n")
            self._qmp_request(stream, "cont")
            stream.close()
            connection.close()
            return process
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            log.with_suffix(".qemu.status").write_text(str(process.returncode) + "\n")
            self.active_qemu.discard(process)
            raise

    def _check_pressure(self, log_path):
        lines = Path(log_path).read_text(errors="replace").splitlines()
        require(not any(re.search(r"ABSD PANIC:|KERNEL FAULT|FAILED|NIC DISABLED", line)
                        for line in lines), f"network serial contains a failure record: {log_path}")
        pressure = [line for line in lines if line.startswith("SMP USER PRESSURE ")]
        if self.baseline_up:
            require(not pressure, f"single-vCPU baseline unexpectedly reported AP pressure: {pressure}")
            require(not any(line.startswith("SMP TIMER SUMMARY cpu=1 ") for line in lines),
                    "single-vCPU baseline unexpectedly reported an AP timer summary")
            require(lines.count("ABSD BOOT OK") == 1,
                    f"single-vCPU baseline lacks exactly one successful boot record: {log_path}")
            return
        require(len(pressure) == 1, f"expected one SMP USER PRESSURE record, found {pressure}")
        values = {key: int(value) for key, value in re.findall(r"([a-z0-9-]+)=([0-9]+)", pressure[0])}
        require(values.get("calls1", 0) > 0, f"no AP ring-3 syscall progress: {pressure[0]}")
        timer = [line for line in lines if line.startswith("SMP TIMER SUMMARY cpu=1 ")]
        require(len(timer) == 1, f"expected one AP timer summary, found {timer}")
        values = {key: int(value) for key, value in re.findall(r"([a-z0-9-]+)=([0-9]+)", timer[0])}
        require(values.get("user-irqs", 0) > 0 and values.get("switches1", 0) > 0,
                f"AP user timer preemption missing: {timer[0]}")
        require(lines.count("ABSD BOOT OK") <= 1, f"duplicate ABSD BOOT OK in {log_path}")

    def _check_bsp_pressure(self, log_path, receipt):
        checker = self.kernel / "scripts/check-smp-bsp-pressure.py"
        require(checker.is_file(), f"missing BSP pressure receipt checker: {checker}")
        output = Path(log_path).with_suffix(".bsp-pressure-oracle.log")
        command = [sys.executable, str(checker), "--serial", str(log_path),
                   "--placement", receipt["placement"], "--cpus", str(self.cpus),
                   "--mode", "durable"]
        result = subprocess.run(command, cwd=self.kernel, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                check=False)
        output.write_text(result.stdout)
        Path(log_path).with_suffix(".bsp-pressure-oracle.status").write_text(
            str(result.returncode) + "\n")
        require(result.returncode == 0,
                f"BSP pressure receipt rejected; see {output}: {result.stdout.strip()}")
        print(result.stdout.rstrip(), flush=True)

    def _finish_boot(self, process, log_path, done_pattern):
        receipt = self.qemu_receipts.get(process)
        finished = None
        usage = None
        try:
            result = self.original_finish(process, log_path, done_pattern)
            # Freeze QEMU child accounting before starting the Python receipt
            # checker. Its CPU time must not become reported QEMU CPU time.
            finished = time.monotonic()
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            self._check_pressure(log_path)
            if self.bsp_pressure and receipt:
                self._check_bsp_pressure(log_path, receipt)
            return result
        finally:
            if receipt and process.poll() is not None:
                Path(receipt["status"]).write_text(str(process.returncode) + "\n")
                if not any(row.get("log") == str(log_path) for row in self.boot_records):
                    if usage is None:
                        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                    if finished is None:
                        finished = time.monotonic()
                    self.boot_records.append({
                        "mode": receipt["mode"], "log": str(log_path),
                        "qemu_exit_status": process.returncode,
                        "qemu_wall_seconds": finished - receipt["started_monotonic"],
                        "qemu_user_seconds": usage.ru_utime - receipt["children_usage_before"].ru_utime,
                        "qemu_system_seconds": usage.ru_stime - receipt["children_usage_before"].ru_stime,
                    })
                self.active_qemu.discard(process)

    def _install_hooks(self):
        self.original_finish = self.matrix.finish_boot
        self.original_phases = {}
        for phase in ("frames", "tcp"):
            original = getattr(self.matrix, f"run_{phase}")
            self.original_phases[phase] = original
            setattr(self.matrix, f"run_{phase}", self._timed_phase(phase, original))
        self.matrix.build_iso = self._build_iso
        self.matrix.start_qemu = self._start_qemu
        self.matrix.finish_boot = self._finish_boot

    def _timed_phase(self, name, function):
        def wrapped(*args, **kwargs):
            started = time.monotonic()
            record = {"phase": name}
            try:
                return function(*args, **kwargs)
            finally:
                record["wall_seconds"] = time.monotonic() - started
                self.phase_records.append(record)
        return wrapped

    def run(self, phases):
        sys.argv = [str(self.platform_script), str(self.kernel), str(self.elf), str(self.work)]
        if phases != {"frames", "tcp"}:
            sys.argv += ["--only", ",".join(sorted(phases))]
        self.matrix.main()

    def write_results(self, status, error=None):
        results = {
            "status": status,
            "mode": ("baseline-up" if self.baseline_up else
                     f"bsp-pressure-{self.cpus}" if self.bsp_pressure else "ap-pressure"),
            "kernel": str(self.kernel), "inputs": str(self.inputs),
            "started_monotonic": self.started,
            "end_to_end_wall_seconds": time.monotonic() - self.started,
            "phases": self.phase_records, "boots": self.boot_records,
            "comparison_scope": ("whole end-to-end network phase, including readiness, protocol "
                                 "checks and deliberate waits; not bulk-only throughput"),
            "deliberate_waits": [
                "frame-phase silence check waits 1.0 s; protocol receive/readiness deadlines are up to 5.0 s",
                "TCP backpressure polling uses 0.2 s intervals and bounded progress sampling",
                "TCP reset/reconnect checks include 0.5 s and 1.0 s settle waits",
                "TCP reconnect validation includes a 1.0 s post-loop stability wait",
            ],
        }
        if error is not None:
            results["error"] = repr(error)
        tmp = self.work / "results.json.tmp"
        tmp.write_text(json.dumps(results, indent=2) + "\n")
        os.replace(tmp, self.work / "results.json")

    def cleanup(self):
        for process in tuple(self.active_qemu):
            if process.poll() is None:
                process.kill()
                process.wait()
            receipt = self.qemu_receipts.get(process)
            if receipt:
                Path(receipt["status"]).write_text(str(process.returncode) + "\n")
            self.active_qemu.discard(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True, help="isolated kernel worktree")
    parser.add_argument("--inputs", type=Path, required=True,
                        help="sealed copied platform root with scripts/net-matrix.py and fixtures")
    parser.add_argument("--work", type=Path, required=True,
                        help="new campaign-owned output directory")
    parser.add_argument("--target", type=Path, required=True,
                        help="campaign-owned Cargo target directory")
    parser.add_argument("--only", default="frames,tcp", help="comma-separated subset: frames,tcp")
    parser.add_argument("--baseline-up", action="store_true",
                        help="one-vCPU normal durable net boot without AP pressure/preemption flags")
    parser.add_argument("--cpus", type=int, choices=(4, 6),
                        help="add a closed 4/6-vCPU BSP-observed AP pressure run")
    args = parser.parse_args()
    work = args.work.resolve()
    build_feature = os.environ.get("SMP_BUILD_FEATURE", "smp-user-test")
    cpus = args.cpus if args.cpus is not None else (1 if args.baseline_up else 2)
    phases = set(args.only.split(","))
    require(phases in ({"frames", "tcp"}, {"frames"}, {"tcp"}),
            f"invalid --only selection: {args.only}")
    require(not (args.baseline_up and args.cpus is not None),
            "--baseline-up cannot be combined with --cpus")
    require(build_feature in ("smp-user-test", "smp-scheduler-test"),
            f"unknown SMP_BUILD_FEATURE: {build_feature}")
    require(cpus not in (4, 6) or build_feature == "smp-scheduler-test",
            "4/6-vCPU network pressure requires SMP_BUILD_FEATURE=smp-scheduler-test")
    require(not (args.baseline_up and build_feature == "smp-scheduler-test"),
            "modern scheduler network case requires two CPUs")
    if work.exists():
        print(f"smp-net-matrix: refusing existing work path: {work}", file=sys.stderr)
        return 1
    work.mkdir(parents=True, exist_ok=False)
    producer = None
    result = 1
    error_record = None
    try:
        producer = Producer(args.kernel, args.inputs, work, args.target,
                            args.baseline_up, cpus, build_feature)
        producer.run(phases)
        result = 0
    except BaseException as error:
        print(f"smp-net-matrix: {error!r}", file=sys.stderr)
        result = 1
        error_record = error
    finally:
        if producer is not None:
            producer.cleanup()
            producer.write_results("passed" if result == 0 else "failed", error_record)
        temporary = work / "run.status.tmp"
        temporary.write_text(f"{result}\n")
        os.replace(temporary, work / "run.status")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
