#!/usr/bin/env python3
"""Host tests of scripts/media.py: no compiler, no image tools, no QEMU.

Against S4's retained candidate (/nonexistent/absd-s4-candidate,
skipped when absent), the generalised z2-usb profile must regenerate every
file S4 put on the ESP, byte for byte, apart from the GRUB loader (built on
the media host): PAIR.JSON, GRUB.CFG, README.TXT, the notices, the runtime
inputs and the kernel. It must also derive S4's GUIDs and epoch from the
pair. The refusals are driven against a WORK whose kernel is a shared
clone of S4's clean kernel checkout. ABSD_REQUIRE_S4=1 makes a missing S4
candidate (or any other skip) a failure; the last line always counts skips.
ABSD_MEDIA_E2E=1 (set by scripts/check-all.sh) runs the end-to-end refusals,
which assemble real images without compiling or booting anything.

    python3 -I scripts/test_media.py
"""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import media  # noqa: E402
import media_operator  # noqa: E402
import media_test_copy  # noqa: E402

S4 = pathlib.Path(os.environ.get("ABSD_S4_CANDIDATE", "/nonexistent/absd-s4-candidate"))
PLATFORM_REPO = pathlib.Path(os.environ.get("ABSD_PLATFORM_REPO", here.parent))
KERNEL = "f8184cae7dd6a097f47331fb763c2f5fdae770cc"
PLATFORM = "bf8c7583b830ccab0982cf36b336086912a0a900"
RUSTC = "rustc 1.98.0 (88d9e12ae 2026-08-18)"


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


@unittest.skipUnless((S4 / "inputs/COMPONENTS.json").is_file(), "S4 candidate not present")
class S4Equivalence(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-"))
        self.work = self.tmp / "work"
        self.work.mkdir()
        kernel = self.work / "kernel"
        subprocess.run(["git", "clone", "-q", "--shared", "--no-checkout", str(S4 / "kernel"), str(kernel)], check=True)
        subprocess.run(["git", "-C", str(kernel), "checkout", "-q", "--detach", KERNEL], check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stage(self, **overrides):
        args = dict(profile="z2-usb", work=str(self.work), kernel_commit=KERNEL, platform_commit=PLATFORM,
                    platform_repo=str(PLATFORM_REPO), probe=str(S4 / "inputs/probe.elf"),
                    probe_receipt=str(S4 / "inputs/RUNTIME-CORRESPONDENCE.json"), input=str(S4 / "inputs/input.txt"),
                    expected=str(S4 / "inputs/expected.txt"))
        args.update(overrides)
        media.stage(type("Args", (), args))

    def refused(self, text, **overrides):
        with self.assertRaises(media.Refused) as caught:
            self.stage(**overrides)
        self.assertIn(text, str(caught.exception))

    def test_guids_and_epoch_derive_from_the_pair(self):
        self.assertEqual(media.guid("ab5d1015", KERNEL, PLATFORM, 1), "ab5d1015-bf8c-4583-8818-000000000001")
        self.assertEqual(media.guid("ab5d1015", KERNEL, PLATFORM, 2), "ab5d1015-bf8c-4583-8818-000000000002")
        self.stage()
        record = json.loads((self.work / media.STAGE_RECORD).read_text())
        self.assertEqual(record["source_date_epoch"], 1792052576)

    def test_every_staged_esp_file_matches_s4_byte_for_byte(self):
        self.stage()
        inputs = self.work / "inputs"
        shutil.copyfile(S4 / "inputs/kernel.elf", inputs / "kernel.elf")  # the kernel build is the media host's
        (inputs / "rustc.txt").write_text(RUSTC + "\n")
        work, record, profile = media.staged(self.work)
        out = self.tmp / "out"
        out.mkdir()
        stage_dir, early = media.fat_stage(work, record, profile, out)
        s4 = json.loads((S4 / "FILE-MANIFEST.json").read_text())
        ours = {str(p.relative_to(stage_dir)): sha(p) for p in sorted(stage_dir.rglob("*")) if p.is_file()}
        expected = {k: v["sha256"] for k, v in s4.items() if k != "EFI/BOOT/BOOTX64.EFI"}
        self.assertEqual(ours, expected)
        self.assertEqual(early.read_bytes(), (S4 / "inputs/EARLY.CFG").read_bytes())
        self.assertEqual((stage_dir / "PAIR.JSON").read_bytes(), (S4 / "inputs/COMPONENTS.json").read_bytes())

    def test_notices_come_from_the_pair_and_the_host(self):
        self.stage()
        for p in sorted((S4 / "inputs/notices").iterdir()):
            self.assertEqual((self.work / "inputs/notices" / p.name).read_bytes(), p.read_bytes(), p.name)

    def test_stage_refuses_another_kernel_commit(self):
        self.refused("pair_mismatch kernel checkout is at f8184cae7dd6", kernel_commit="0" * 40)

    def test_stage_refuses_a_platform_commit_the_repository_lacks(self):
        self.refused("pair_mismatch platform commit", platform_commit="1" * 40)

    def test_stage_refuses_a_probe_receipt_for_another_platform(self):
        receipt = json.loads((S4 / "inputs/RUNTIME-CORRESPONDENCE.json").read_text())
        receipt["requested_source"] = "2" * 40
        path = self.tmp / "receipt.json"
        path.write_text(json.dumps(receipt))
        self.refused("pair_mismatch the probe receipt is for platform 222222222222", probe_receipt=str(path))

    def test_stage_refuses_a_probe_other_than_its_receipt_names(self):
        other = self.tmp / "probe.elf"
        other.write_bytes(b"\x7fELF\x02" + b"\0" * 64)
        self.refused("probe_mismatch the probe ELF is not the one its receipt names", probe=str(other))

    def test_stage_refuses_an_invalid_commit(self):
        self.refused("pair_invalid kernel", kernel_commit="f8184ca")

    def test_stage_refuses_a_second_stage(self):
        self.stage()
        self.refused("stage_exists")

    def test_later_steps_refuse_changed_inputs(self):
        self.stage()
        (self.work / "inputs/input.txt").write_bytes(b"changed\n")
        with self.assertRaises(media.Refused) as caught:
            media.staged(self.work)
        self.assertIn("stage_changed inputs/input.txt", str(caught.exception))

    def test_stage_refuses_a_kernel_checkout_that_is_a_link(self):
        shutil.rmtree(self.work / "kernel")
        (self.work / "kernel").symlink_to(S4 / "kernel")
        self.refused("kernel_checkout_missing")

    def test_later_steps_refuse_a_changed_notice(self):
        self.stage()
        notice = sorted((self.work / "inputs/notices").iterdir())[0]
        notice.write_bytes(notice.read_bytes() + b"x")
        with self.assertRaises(media.Refused) as caught:
            media.staged(self.work)
        self.assertIn(f"stage_changed inputs/notices/{notice.name}", str(caught.exception))

    def test_image_steps_refuse_a_kernel_without_its_build_record(self):
        self.stage()
        shutil.copyfile(S4 / "inputs/kernel.elf", self.work / "inputs/kernel.elf")
        work, record, profile = media.staged(self.work)
        with self.assertRaises(media.Refused) as caught:
            media.bound_kernel(work, record, profile)
        self.assertIn("kernel_missing", str(caught.exception))

    def test_image_steps_refuse_a_substituted_kernel(self):
        self.stage()
        work, record, profile = media.staged(self.work)
        inputs = work / "inputs"
        output = work / "kernel" / media.KERNEL_OUTPUT
        output.parent.mkdir(parents=True)
        shutil.copyfile(S4 / "inputs/kernel.elf", output)
        shutil.copyfile(output, inputs / "kernel.elf")
        build = dict(media.kernel_binding(work, record, profile), elf_sha256=sha(output))
        (inputs / media.KERNEL_BUILD).write_text(json.dumps(build))
        self.assertEqual(media.bound_kernel(work, record, profile)["elf_sha256"], sha(output))
        (inputs / "kernel.elf").write_bytes((inputs / "kernel.elf").read_bytes() + b"\0")
        with self.assertRaises(media.Refused) as caught:
            media.bound_kernel(work, record, profile)
        self.assertIn("kernel_unbound inputs/kernel.elf", str(caught.exception))
        shutil.copyfile(output, inputs / "kernel.elf")
        (inputs / media.KERNEL_BUILD).write_text(json.dumps(dict(build, features=["other"])))
        with self.assertRaises(media.Refused) as caught:
            media.bound_kernel(work, record, profile)
        self.assertIn("kernel_unbound the kernel build record is for another stage", str(caught.exception))

    def test_pair_record_refuses_a_kernel_without_the_probe(self):
        self.stage()
        inputs = self.work / "inputs"
        (inputs / "kernel.elf").write_bytes(b"\x7fELF\x02 no probe here")
        (inputs / "rustc.txt").write_text(RUSTC + "\n")
        work, record, profile = media.staged(self.work)
        with self.assertRaises(media.Refused) as caught:
            media.pair_record(record, profile, inputs)
        self.assertIn("probe_not_embedded", str(caught.exception))


class CopyOrder(unittest.TestCase):
    """The ESP copy order (media.copy_order): host-independent, complete, parents first."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-order-"))
        for name in ("b/z.txt", "b/a.txt", "a.txt", "c/d/e.txt"):
            path = self.tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unpinned_order_is_a_sorted_preorder_walk(self):
        self.assertEqual(media.copy_order(self.tmp, {}),
                         ["a.txt", "b/", "b/a.txt", "b/z.txt", "c/", "c/d/", "c/d/e.txt"])

    def test_a_pinned_order_is_used_as_given(self):
        order = ["c/", "c/d/", "c/d/e.txt", "b/", "b/z.txt", "b/a.txt", "a.txt"]
        self.assertEqual(media.copy_order(self.tmp, {"fat": {"order": order}}), order)

    def test_a_pinned_order_must_cover_exactly_the_staged_entries(self):
        with self.assertRaises(media.Refused) as caught:
            media.copy_order(self.tmp, {"fat": {"order": ["a.txt", "b/", "b/a.txt", "c/", "c/d/", "c/d/e.txt"]}})
        self.assertIn("missing ['b/z.txt']", str(caught.exception))

    def test_a_pinned_order_must_create_a_directory_before_its_contents(self):
        with self.assertRaises(media.Refused) as caught:
            media.copy_order(self.tmp, {"fat": {"order": ["b/a.txt", "b/", "b/z.txt", "a.txt", "c/", "c/d/", "c/d/e.txt"]}})
        self.assertIn("before its directory", str(caught.exception))

    def test_the_z2_profile_pins_s4s_compression_preset(self):
        self.assertEqual(media.load_profile("z2-usb")["compact"]["xz_preset"], 0)

    def test_the_z2_profile_pins_an_order_over_its_esp(self):
        order = media.load_profile("z2-usb")["fat"]["order"]
        self.assertEqual(len(order), len(set(order)))
        self.assertIn("EFI/BOOT/BOOTX64.EFI", order)
        self.assertEqual(sum(1 for e in order if not e.endswith("/")), 15)


class Confinement(unittest.TestCase):
    """Receipt-supplied names, short reads, the build environment and pins."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-confine-"))
        (self.tmp / "image.img").write_bytes(b"x" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_receipt_names_must_be_plain_regular_files_inside_out(self):
        self.assertEqual(media.confined(self.tmp, "image.img"), self.tmp / "image.img")
        (self.tmp / "link.img").symlink_to(self.tmp / "image.img")
        for name in ("../image.img", "/dev/sda", "sub/image.img", "..", "", "a,b.img", "link.img", "absent.img"):
            with self.assertRaises(media.Refused, msg=name):
                media.confined(self.tmp, name)

    def test_a_short_source_is_refused_not_looped_on(self):
        media.copy_exact(self.tmp / "image.img", self.tmp / "part", 10, 90)
        self.assertEqual((self.tmp / "part").read_bytes(), b"x" * 90)
        with self.assertRaises(media.Refused) as caught:
            media.copy_exact(self.tmp / "image.img", self.tmp / "part2", 10, 200)
        self.assertIn("truncated", str(caught.exception))

    def test_the_build_environment_drops_ambient_settings(self):
        os.environ["XZ_OPT"] = "--block-size=1024"
        os.environ["XZ_DEFAULTS"] = "-9"
        try:
            env = media.clean_env(1792052576, CARGO_BUILD_JOBS=1)
        finally:
            del os.environ["XZ_OPT"], os.environ["XZ_DEFAULTS"]
        self.assertNotIn("XZ_OPT", env)
        self.assertNotIn("XZ_DEFAULTS", env)
        self.assertEqual({k: env[k] for k in ("LC_ALL", "TZ", "SOURCE_DATE_EPOCH", "MTOOLSRC", "CARGO_BUILD_JOBS")},
                         {"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1792052576", "MTOOLSRC": "/dev/null",
                          "CARGO_BUILD_JOBS": "1"})
        self.assertEqual(set(env), {"PATH", "HOME", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH", "MTOOLSRC", "CARGO_BUILD_JOBS"})
        self.assertEqual((env["PATH"], env["HOME"]), (media.SYSTEM_PATH, "/nonexistent"))

    @unittest.skipUnless(shutil.which("dpkg-query") and shutil.which("xz", path=media.SYSTEM_PATH), "no dpkg or xz")
    def test_tools_come_from_the_system_path_and_their_package(self):
        shadow = self.tmp / "bin"
        shadow.mkdir()
        (shadow / "xz").write_text("#!/bin/sh\nexit 0\n")
        (shadow / "xz").chmod(0o755)
        saved_path, saved_tools = os.environ["PATH"], dict(media._TOOLS)
        os.environ["PATH"] = f"{shadow}:{saved_path}"
        media._TOOLS.clear()
        try:
            found = media.tool("xz")
            self.assertNotEqual(pathlib.Path(found).parent, shadow)
            self.assertEqual(media.tools_used()["xz"]["package"], "xz-utils")
            media._TOOLS.clear()
            media.TOOL_PACKAGES["xz"] = "bash"
            with self.assertRaises(media.Refused) as caught:
                media.tool("xz")
            self.assertIn("tool_unowned", str(caught.exception))
        finally:
            media.TOOL_PACKAGES["xz"] = "xz-utils"
            os.environ["PATH"] = saved_path
            media._TOOLS.clear()
            media._TOOLS.update(saved_tools)

    def test_pair_json_must_name_exactly_the_staged_inputs(self):
        inputs = self.tmp / "inputs"
        inputs.mkdir()
        files = {}
        for name in media.PAIR_FILES:
            (inputs / name).write_bytes(name.encode())
            files[name] = {"sha256": sha(inputs / name)}
        media.check_pair_files({"files": files}, inputs)
        (self.tmp / "outside").write_bytes(b"outside")
        bad = [{}, {"files": {}}, {"files": "x"},
               {"files": dict(files, **{"/etc/passwd": {"sha256": "0"}})},
               {"files": dict(files, **{"../outside": {"sha256": sha(self.tmp / "outside")}})},
               {"files": {k: v for k, v in files.items() if k != "probe.elf"}},
               {"files": dict(files, **{"probe.elf": {"sha256": "0" * 64}})},
               {"files": dict(files, **{"probe.elf": "not a record"})}]
        for pair in bad:
            with self.assertRaises(media.Refused, msg=repr(pair)[:80]):
                media.check_pair_files(pair, inputs)
        (inputs / "kernel.elf").unlink()
        (inputs / "kernel.elf").symlink_to(self.tmp / "outside")
        with self.assertRaises(media.Refused):
            media.check_pair_files({"files": files}, inputs)

    def test_pins_refuse_another_version_before_building(self):
        real = media.package_versions
        media.package_versions = lambda names, env=None: {"mtools": "4.0.43-1build1", "xz-utils": "5.8.0"}
        try:
            profile = {"pins": {"packages": {"mtools": "4.0.43-1build1", "xz-utils": "5.6.1+really5.4.5-1ubuntu0.3"}}}
            with self.assertRaises(media.Refused) as caught:
                media.check_pins(profile)
            self.assertIn("pins_mismatch xz-utils wants 5.6.1+really5.4.5-1ubuntu0.3 has 5.8.0", str(caught.exception))
            profile["pins"]["packages"]["xz-utils"] = "5.8.0"
            self.assertEqual(media.check_pins(profile)["packages"]["xz-utils"], "5.8.0")
            del profile["pins"]["packages"]["mtools"]
            media.package_versions = lambda names, env=None: {}
            with self.assertRaises(media.Refused):
                media.check_pins(profile)
        finally:
            media.package_versions = real

    def test_the_toolchain_comes_from_its_pinned_location_at_its_pinned_digests(self):
        bin_dir = self.tmp / "rh" / "toolchains" / "tc" / "bin"
        bin_dir.mkdir(parents=True)
        for name in ("rustc", "cargo"):
            (bin_dir / name).write_bytes(name.encode())
        profile = {"pins": {"rust": {"rustup_home": str(self.tmp / "rh"), "toolchain": "tc",
                                     "rustc_sha256": sha(bin_dir / "rustc"), "cargo_sha256": sha(bin_dir / "cargo")}}}
        found_dir, found = media.rust_toolchain(profile)
        self.assertEqual(found_dir, bin_dir.resolve())
        env = media.rust_env(self.tmp, 1, profile)
        self.assertEqual(env["PATH"], f"{bin_dir.resolve()}:{media.SYSTEM_PATH}")
        self.assertEqual(env["HOME"], str(self.tmp / "home"))
        self.assertFalse(any(k.startswith("RUSTUP") for k in env))
        (self.tmp / "home" / "stale").write_text("x")
        media.rust_env(self.tmp, 1, profile)
        self.assertEqual(list((self.tmp / "home").iterdir()), [])
        shutil.rmtree(self.tmp / "home")
        (self.tmp / "home").symlink_to(self.tmp)
        with self.assertRaises(media.Refused):
            media.rust_env(self.tmp, 1, profile)
        (self.tmp / "home").unlink()
        (bin_dir / "cargo").write_bytes(b"other cargo")
        with self.assertRaises(media.Refused) as caught:
            media.rust_toolchain(profile)
        self.assertIn("pins_mismatch", str(caught.exception))
        (bin_dir / "cargo").unlink()
        with self.assertRaises(media.Refused) as caught:
            media.rust_toolchain(profile)
        self.assertIn("tool_missing", str(caught.exception))
        with self.assertRaises(media.Refused):
            media.rust_toolchain({"pins": {}})

    def test_the_z2_profile_pins_the_image_tools(self):
        pins = media.load_profile("z2-usb")["pins"]
        for package in ("grub-efi-amd64-bin", "mtools", "dosfstools", "gdisk", "xz-utils"):
            self.assertIn(package, pins["packages"])
        self.assertTrue(pins["rustc"].startswith("rustc 1.98.0"))
        self.assertEqual(pins["rust"]["toolchain"], "1.98.0-x86_64-unknown-linux-gnu")
        self.assertEqual(len(pins["rust"]["cargo_sha256"]), 64)


E2E = os.environ.get("ABSD_MEDIA_E2E") == "1"


@unittest.skipUnless(E2E and (S4 / "inputs/COMPONENTS.json").is_file(),
                     "end-to-end media refusals need ABSD_MEDIA_E2E=1, the S4 candidate and the pinned image tools")
class EndToEnd(unittest.TestCase):
    """Real image/validate/boot refusals on two WORKs: A with S4's kernel
    ELF, B with a different ELF (one byte appended, the probe still
    embedded once). No QEMU runs: every case refuses before it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-e2e-"))
        cls.elf = {"a": (S4 / "inputs/kernel.elf").read_bytes()}
        cls.elf["b"] = cls.elf["a"] + b"\0"
        for name in ("a", "b"):
            work = cls.tmp / name
            work.mkdir()
            kernel = work / "kernel"
            subprocess.run(["git", "clone", "-q", "--shared", "--no-checkout", str(S4 / "kernel"), str(kernel)], check=True)
            subprocess.run(["git", "-C", str(kernel), "checkout", "-q", "--detach", KERNEL], check=True)
            media.stage(type("Args", (), dict(
                profile="z2-usb", work=str(work), kernel_commit=KERNEL, platform_commit=PLATFORM,
                platform_repo=str(PLATFORM_REPO), probe=str(S4 / "inputs/probe.elf"),
                probe_receipt=str(S4 / "inputs/RUNTIME-CORRESPONDENCE.json"), input=str(S4 / "inputs/input.txt"),
                expected=str(S4 / "inputs/expected.txt"))))
            cls.fake_kernel(work, cls.elf[name])
            media.image(type("Args", (), dict(work=str(work), out=str(cls.tmp / f"out-{name}"))))
            media.validate(type("Args", (), dict(work=str(work), out=str(cls.tmp / f"out-{name}"))))

    @staticmethod
    def fake_kernel(work, elf):
        """What `media.py kernel` leaves, without compiling: the ELF in the
        checkout's output and inputs/, and its build record."""
        work, record, profile = media.staged(work)
        output = work / "kernel" / media.KERNEL_OUTPUT
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(elf)
        shutil.copyfile(output, work / "inputs/kernel.elf")
        (work / "inputs/rustc.txt").write_text(RUSTC + "\n")
        build = dict(media.kernel_binding(work, record, profile), elf_sha256=sha(output))
        (work / "inputs" / media.KERNEL_BUILD).write_text(json.dumps(build))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def args(self, work, out, results=None):
        return type("Args", (), dict(work=str(self.tmp / work), out=str(out),
                                     results=str(results or tempfile.mktemp(dir=self.tmp))))

    def refuses(self, step, args, text):
        with self.assertRaises(media.Refused) as caught:
            step(args)
        self.assertIn(text, str(caught.exception))

    def copy_out(self, name):
        target = pathlib.Path(tempfile.mkdtemp(dir=self.tmp)) / "out"
        shutil.copytree(self.tmp / f"out-{name}", target, copy_function=media_test_copy.copy2)
        return target

    def test_boot_refuses_another_works_validated_output(self):
        self.refuses(media.boot, self.args("b", self.tmp / "out-a"), "receipt_mismatch")
        self.refuses(media.boot, self.args("a", self.tmp / "out-b"), "receipt_mismatch")

    def test_boot_refuses_a_validation_for_another_stage(self):
        out = self.copy_out("a")
        validation = json.loads((out / "VALIDATION.json").read_text())
        validation["identity"]["stage_sha256"] = "0" * 64
        (out / "VALIDATION.json").write_text(json.dumps(validation))
        self.refuses(media.boot, self.args("a", out), "not_validated the validation is for another stage")

    def test_a_checkout_output_swap_is_refused_by_image_validate_and_boot(self):
        output = self.tmp / "a" / "kernel" / media.KERNEL_OUTPUT
        try:
            output.write_bytes(self.elf["b"])
            self.refuses(media.image, self.args("a", self.tmp / "never"), "kernel_unbound the checkout's build output")
            self.refuses(media.validate, self.args("a", self.copy_out("a")), "kernel_unbound the checkout's build output")
            self.refuses(media.boot, self.args("a", self.tmp / "out-a"), "kernel_unbound the checkout's build output")
        finally:
            output.write_bytes(self.elf["a"])

    def test_validate_refuses_a_tampered_compressed_image(self):
        out = self.copy_out("a")
        receipt = json.loads((out / "MEDIA-RECEIPT.json").read_text())
        xz = out / receipt["compact"]["name"]
        data = bytearray(xz.read_bytes())
        data[len(data) // 2] ^= 0xFF
        xz.write_bytes(bytes(data))
        self.refuses(media.validate, self.args("a", out), "compact_changed")
        receipt["compact"]["sha256"] = sha(xz)
        (out / "MEDIA-RECEIPT.json").write_text(json.dumps(receipt))
        self.refuses(media.validate, self.args("a", out), "compact_mismatch")

    def test_validate_refuses_a_retabled_gpt_even_with_a_matching_receipt(self):
        out = self.copy_out("a")
        receipt = json.loads((out / "MEDIA-RECEIPT.json").read_text())
        disk = out / receipt["image"]["name"]
        subprocess.run([media.tool("sgdisk"), "--partition-guid=1:00000000-1111-4222-8333-444444444444", str(disk)],
                       check=True, capture_output=True, env=media.clean_env(0))
        self.refuses(media.validate, self.args("a", out), "image_changed")
        receipt["image"]["sha256"] = sha(disk)
        (out / "MEDIA-RECEIPT.json").write_text(json.dumps(receipt))
        self.refuses(media.validate, self.args("a", out), "layout_mismatch")


U1B = pathlib.Path(os.environ.get("ABSD_U1B_IMAGE", "/nonexistent/absd-u1b-image"))


class OperatorDisk(unittest.TestCase):
    """The vm-operator recipe's own transformations."""

    @unittest.skipUnless((U1B / "absd-operator.img").is_file(), "U1-b reference image not present")
    def test_fs_id_is_read_and_substituted_with_every_digest(self):
        data = (U1B / "absd-operator.img").read_bytes()
        original = media_operator.fs_id_of(U1B / "absd-operator.img")
        changed = media_operator.with_fs_id(data, 0x0123456789ABCDEF)
        self.assertNotEqual(changed, data)
        self.assertEqual(len(media_operator.superblocks(changed)), len(media_operator.superblocks(data)))
        self.assertEqual(media_operator.with_fs_id(changed, original), data)

    @unittest.skipUnless(shutil.which("mformat") and shutil.which("mcopy"), "mtools not present")
    def test_efi_normalisation_zeroes_free_space_and_sets_the_serial(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-efi-"))
        try:
            fat = tmp / "efi.img"
            env = media.clean_env(0)
            subprocess.run(["mformat", "-C", "-f", "2880", "-L", "16", "-N", "12345678", "-i", str(fat), "::"],
                           check=True, env=env)
            (tmp / "BOOTX64.EFI").write_bytes(b"\x4d\x5a" + bytes(range(256)) * 300)
            subprocess.run(["mmd", "-i", str(fat), "::/efi"], check=True, env=env)
            subprocess.run(["mcopy", "-i", str(fat), str(tmp / "BOOTX64.EFI"), "::/efi/BOOTX64.EFI"], check=True, env=env)
            size = fat.stat().st_size
            iso = tmp / "fake.iso"
            raw = bytearray(4096) + bytearray(fat.read_bytes())
            raw[4096 + size - 100:4096 + size - 50] = b"\xaa" * 50   # leaked memory in the slack/free space
            iso.write_bytes(bytes(raw))
            media_operator.normalize_efi(iso, 2, size, 0xAB5DBFF8)
            out = iso.read_bytes()[4096:]
            self.assertEqual(out[39:43], (0xAB5DBFF8).to_bytes(4, "little"))
            self.assertEqual(out[size - 100:size - 50], bytes(50))
            normalized = tmp / "normalized.img"
            normalized.write_bytes(out)
            listing = subprocess.run(["mtype", "-i", str(normalized), "::/efi/BOOTX64.EFI"], capture_output=True,
                                     check=True, env=env).stdout
            self.assertEqual(listing, (tmp / "BOOTX64.EFI").read_bytes())
            with self.assertRaises(media.Refused):
                media_operator.normalize_efi(iso, 0, size, 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_console_chunks_are_decoded_in_order(self):
        line = lambda off, text: b"EXTERNAL OUTPUT CHUNK offset=%016x data=%s\n" % (off, text.encode().hex().encode())
        serial = b"noise\n" + line(0, "SSH LIST") + b"other\n" + line(8, "ENING port=22\n") + line(99, "lost")
        self.assertEqual(media_operator.captured(serial), "SSH LISTENING port=22\n")

    def test_read_only_extracted_trees_are_removed(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-ro-"))
        (tmp / "x/y").mkdir(parents=True)
        (tmp / "x/y/f").write_text("f")
        os.chmod(tmp / "x/y", 0o555)
        os.chmod(tmp / "x", 0o555)
        media_operator.remove_tree(tmp / "x")
        self.assertFalse((tmp / "x").exists())
        (tmp / "link").symlink_to(tmp)
        with self.assertRaises(media.Refused):
            media_operator.remove_tree(tmp / "link")
        shutil.rmtree(tmp)

    def test_manifest_parts_split_header_and_files(self):
        head, files = media_operator.manifest_parts("platform a\nkernel b\nrelease dev\niso c\nfile d /bin/x y\n")
        self.assertEqual(head, {"platform": "a", "kernel": "b", "release": "dev", "iso": "c"})
        self.assertEqual(files, {"/bin/x y": "d"})


@unittest.skipUnless(all(pathlib.Path(d).is_dir() for d in media_operator.GRUB_MODULES)
                     and shutil.which("git", path=media.SYSTEM_PATH), "GRUB module directories or git not present")
class OperatorRefusals(unittest.TestCase):
    """The operator path's binding, confinement, environment and pins,
    against a fake kernel checkout and platform tree (nothing compiled)."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-operator-"))
        self.profile = media_operator.load_operator_profile("vm-operator")
        self.kernel, self.platform = self.tmp / "kernel", self.tmp / "platform"
        env = media.clean_env(0, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                              GIT_COMMITTER_EMAIL="t@t")
        for repo in (self.kernel, self.platform):
            repo.mkdir()
            (repo / "SOURCE").write_text(repo.name)
            for argv in (["init", "-q"], ["add", "SOURCE"], ["commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", str(repo), *argv], check=True, env=env, capture_output=True)
        self.elf = b"\x7fELF kernel"
        tree = self.kernel / "build/durable/iso-0"
        (tree / "boot/grub").mkdir(parents=True)
        (tree / "boot/absd-kernel").write_bytes(self.elf)
        (tree / "boot/grub/grub.cfg").write_text("menuentry x {\n  " + self.profile["expect"]["grub_entry"] + "\n}\n")
        output = self.kernel / media_operator.KERNEL_OUTPUT
        output.parent.mkdir(parents=True)
        output.write_bytes(self.elf)
        for name in media_operator.PLATFORM_ELFS:
            (self.platform / name).write_bytes(name.encode())
        head = lambda repo: media.git(repo, "rev-parse", "HEAD").decode().strip()
        self.receipt = {"kernel_commit": head(self.kernel), "platform_commit": head(self.platform),
                        "binding": media_operator.operator_binding(self.platform, self.kernel, self.profile)}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def unbound(self, text):
        with self.assertRaises(media.Refused) as caught:
            media_operator.bound_operator_build(self.platform, self.kernel, self.profile, self.receipt)
        self.assertIn(text, str(caught.exception))

    def test_the_bound_trees_pass(self):
        media_operator.bound_operator_build(self.platform, self.kernel, self.profile, self.receipt)

    def test_a_missing_checkout_output_is_refused(self):
        (self.kernel / media_operator.KERNEL_OUTPUT).unlink()
        self.unbound("build_unbound")

    def test_a_checkout_output_other_than_the_iso_kernel_is_refused(self):
        (self.kernel / media_operator.KERNEL_OUTPUT).write_bytes(b"other")
        self.unbound("not the served-boot kernel")

    def test_a_rebuilt_kernel_is_refused(self):
        for path in (self.kernel / "build/durable/iso-0/boot/absd-kernel", self.kernel / media_operator.KERNEL_OUTPUT):
            path.write_bytes(b"rebuilt")
        self.unbound("iso_tree")

    def test_a_changed_platform_elf_is_refused(self):
        (self.platform / "sshd.elf").write_bytes(b"other sshd")
        self.unbound("platform_elfs")

    def test_an_extra_or_missing_iso_tree_file_is_refused(self):
        (self.kernel / "build/durable/iso-0/boot/extra").write_bytes(b"x")
        self.unbound("iso_tree_unexpected")
        (self.kernel / "build/durable/iso-0/boot/extra").unlink()
        (self.kernel / "build/durable/iso-0/boot/grub/grub.cfg").unlink()
        self.unbound("iso_tree_unexpected")

    def test_another_grub_inventory_is_refused(self):
        self.receipt["binding"]["grub_inventory"] = {"sha256": "0" * 64, "files": 1}
        self.unbound("grub_inventory")

    def test_another_commit_is_refused(self):
        self.receipt["kernel_commit"] = "0" * 40
        self.unbound("pair_mismatch")

    def test_artifacts_must_be_exactly_the_fixed_names(self):
        out = self.tmp / "out"
        out.mkdir()
        for name in media_operator.ARTIFACTS:
            (out / name).write_bytes(name.encode())
        good = {name: {"name": name, "sha256": "x", "bytes": 1} for name in media_operator.ARTIFACTS}
        self.assertEqual(sorted(media_operator.artifact_paths(out, {"artifacts": good})),
                         sorted(media_operator.ARTIFACTS))
        (self.tmp / "elsewhere.img").write_bytes(b"x")
        bad = [dict(good, extra={"name": "extra"}),
               {k: v for k, v in good.items() if k != media_operator.MANIFEST},
               dict(good, **{media_operator.IMAGE: {"name": "../elsewhere.img"}}),
               dict(good, **{media_operator.IMAGE: {"name": media_operator.ISO}}), {}]
        for artifacts in bad:
            with self.assertRaises(media.Refused, msg=repr(artifacts)[:60]) as caught:
                media_operator.artifact_paths(out, {"artifacts": artifacts})
            self.assertIn("receipt_mismatch artifacts must be exactly", str(caught.exception))
        (out / media_operator.IMAGE).unlink()
        (out / media_operator.IMAGE).symlink_to(self.tmp / "elsewhere.img")
        with self.assertRaises(media.Refused) as caught:
            media_operator.artifact_paths(out, {"artifacts": good})
        self.assertIn("path_refused", str(caught.exception))

    def test_iso_tree_names_must_be_exactly_the_profiles(self):
        media_operator.check_iso_tree_names(self.receipt, self.profile)
        tree = self.receipt["binding"]["iso_tree"]
        for names in (dict(tree, **{"../../etc/passwd": "0"}), {"boot/absd-kernel": tree["boot/absd-kernel"]}):
            with self.assertRaises(media.Refused) as caught:
                media_operator.check_iso_tree_names({"binding": {"iso_tree": names}}, self.profile)
            self.assertIn("is not exactly the profile's", str(caught.exception))

    def test_the_build_uses_a_private_offline_cargo_home_and_remaps_the_kernel(self):
        bin_dir = self.tmp / "rh/toolchains/tc/bin"
        bin_dir.mkdir(parents=True)
        for name in ("rustc", "cargo"):
            (bin_dir / name).write_bytes(name.encode())
        profile = dict(self.profile, pins={"rust": {"rustup_home": str(self.tmp / "rh"), "toolchain": "tc",
                                                    "rustc_sha256": sha(bin_dir / "rustc"),
                                                    "cargo_sha256": sha(bin_dir / "cargo")}})
        caller = self.tmp / "caller-cargo"
        caller.mkdir()
        (caller / "config.toml").write_text("[build]\nrustflags = ['-C', 'opt-level=3']\n")
        os.environ["CARGO_HOME"] = str(caller)
        try:
            work = self.tmp / "work"
            work.mkdir()
            env = media_operator.operator_env(work, 1, profile, self.kernel, "dev")
        finally:
            del os.environ["CARGO_HOME"]
        self.assertEqual(env["CARGO_HOME"], str(work / "cargo-home"))
        self.assertEqual(list((work / "cargo-home").iterdir()), [])
        self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(env["RUSTFLAGS"], f"--remap-path-prefix={self.kernel}=/absd/kernel-run")
        self.assertNotIn(str(caller), json.dumps(env))

    def test_validation_checks_pins_before_reading_anything(self):
        real = media.package_versions
        media.package_versions = lambda names, env=None: {}
        try:
            with self.assertRaises(media.Refused) as caught:
                media_operator.operator_validate(type("Args", (), dict(
                    profile="vm-operator", out=str(self.tmp / "absent"), platform_tree=str(self.platform),
                    kernel_run=str(self.kernel))))
            self.assertIn("pins_mismatch", str(caught.exception))
        finally:
            media.package_versions = real

    def test_boot_refuses_a_validation_of_another_build(self):
        out = self.tmp / "out"
        out.mkdir()
        for name in media_operator.ARTIFACTS:
            (out / name).write_bytes(name.encode())
        receipt = dict(self.receipt, profile="vm-operator", profile_sha256=media.profile_sha("vm-operator"),
                       release_id="dev", source_date_epoch=1, fs_id="00",
                       artifacts={n: {"name": n, "sha256": sha(out / n), "bytes": 1} for n in media_operator.ARTIFACTS})
        (out / media_operator.RECEIPT).write_text(json.dumps(receipt))
        other = dict(receipt, fs_id="11")
        validation = {"identity": media_operator.operator_identity(other),
                      "image_sha256": sha(out / media_operator.IMAGE), "iso_sha256": sha(out / media_operator.ISO)}
        (out / media_operator.VALIDATION).write_text(json.dumps(validation))
        args = type("Args", (), dict(profile="vm-operator", out=str(out), results=str(self.tmp / "results"),
                                     platform_tree=str(self.platform), kernel_run=str(self.kernel), login_key=None))
        with self.assertRaises(media.Refused) as caught:
            media_operator.operator_boot(args)
        self.assertIn("not_validated the validation is for another build", str(caught.exception))
        (self.platform / "absd-fsd.elf").write_bytes(b"swapped")
        with self.assertRaises(media.Refused) as caught:
            media_operator.operator_boot(args)
        self.assertIn("build_unbound", str(caught.exception))
        self.assertFalse((self.tmp / "results").exists())


class OperatorGrub(unittest.TestCase):
    """The exact /boot/grub inventory check, against a fake host inventory
    and a fake extracted ISO (media_operator.check_iso_grub)."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-grub-"))
        self.profile = {"iso": {"grub": {"top_level": ["fonts", "grub.cfg", "i386-pc", "locale", "roms", "x86_64-efi"],
                                         "generated": ["i386-pc/eltorito.img"], "font": "unused",
                                         "not_copied": ["i386-pc/kernel.img", "x86_64-efi/kernel.img"]}}}
        self.host = self.tmp / "host"
        self.modules = {}
        for key in ("i386-pc/normal.mod", "i386-pc/moddep.lst", "i386-pc/kernel.img", "x86_64-efi/normal.mod",
                    "x86_64-efi/kernel.img"):
            path = self.host / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key.encode())
            self.modules[key] = sha(path)
        self.grub = self.tmp / "iso/boot/grub"
        for name in ("fonts", "i386-pc", "locale", "roms", "x86_64-efi"):
            (self.grub / name).mkdir(parents=True)
        (self.grub / "grub.cfg").write_text("cfg")
        (self.grub / "fonts/unicode.pf2").write_bytes(b"font")
        self.font = sha(self.grub / "fonts/unicode.pf2")
        for key in ("i386-pc/normal.mod", "i386-pc/moddep.lst", "x86_64-efi/normal.mod"):
            shutil.copyfile(self.host / key, self.grub / key)
        (self.grub / "i386-pc/eltorito.img").write_bytes(b"generated")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def refused(self, text):
        with self.assertRaises(media.Refused) as caught:
            media_operator.check_iso_grub(self.grub, self.profile, self.modules, self.font)
        self.assertIn(text, str(caught.exception))

    def test_the_exact_inventory_passes(self):
        self.assertEqual(media_operator.check_iso_grub(self.grub, self.profile, self.modules, self.font),
                         {"modules": 3, "generated": 1, "font": 1})

    def test_an_unknown_module_is_refused(self):
        (self.grub / "x86_64-efi/evil.mod").write_bytes(b"x")
        self.refused("extra=['x86_64-efi/evil.mod']")

    def test_a_not_copied_host_file_on_the_iso_is_refused(self):
        shutil.copyfile(self.host / "i386-pc/kernel.img", self.grub / "i386-pc/kernel.img")
        self.refused("extra=['i386-pc/kernel.img']")

    def test_a_missing_module_is_refused(self):
        (self.grub / "i386-pc/moddep.lst").unlink()
        self.refused("missing=['i386-pc/moddep.lst']")

    def test_a_missing_generated_file_is_refused(self):
        (self.grub / "i386-pc/eltorito.img").unlink()
        self.refused("missing=['i386-pc/eltorito.img']")

    def test_a_changed_module_is_refused(self):
        (self.grub / "x86_64-efi/normal.mod").write_bytes(b"patched")
        self.refused("changed=['x86_64-efi/normal.mod']")

    def test_an_extra_top_level_entry_is_refused(self):
        (self.grub / "themes").mkdir()
        self.refused("iso_grub_unexpected /boot/grub holds")

    def test_translations_or_roms_are_refused(self):
        (self.grub / "locale/en_GB.mo").write_bytes(b"mo")
        self.refused("locale/ is not empty")

    def test_another_font_is_refused(self):
        (self.grub / "fonts/unicode.pf2").write_bytes(b"other font")
        self.refused("fonts/ holds")

    def test_a_link_in_place_of_a_module_is_refused(self):
        (self.grub / "x86_64-efi/normal.mod").unlink()
        (self.grub / "x86_64-efi/normal.mod").symlink_to(self.host / "x86_64-efi/normal.mod")
        self.refused("is not a regular file")

    def test_a_profile_naming_files_the_host_lacks_is_refused(self):
        self.profile["iso"]["grub"]["not_copied"].append("i386-pc/absent.img")
        self.refused("grub_inventory_unexpected")


OPERATOR_FIXTURE = os.environ.get("ABSD_OPERATOR_FIXTURE")


@unittest.skipUnless(OPERATOR_FIXTURE and os.environ.get("ABSD_OPERATOR_PLATFORM") and
                     os.environ.get("ABSD_OPERATOR_KERNEL"),
                     "operator validation refusals need ABSD_OPERATOR_FIXTURE (a validated operator-image output) "
                     "with ABSD_OPERATOR_PLATFORM and ABSD_OPERATOR_KERNEL, on a host with the profile's pins")
class OperatorValidateGrub(unittest.TestCase):
    """GRUB inventory refusals through operator_validate itself: the
    fixture's ISO is extracted, edited and remastered, the receipt is made
    to name the new ISO, and validation must refuse with the reason."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-media-opgrub-"))
        self.out = self.tmp / "out"
        self.out.mkdir()
        for name in (*media_operator.ARTIFACTS, media_operator.RECEIPT):
            media_test_copy.copyfile(pathlib.Path(OPERATOR_FIXTURE) / name, self.out / name)
        self.extra = self.tmp / "extra.mod"
        self.extra.write_bytes(b"not a GRUB module")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tamper(self, edit):
        """Extracts the ISO, applies `edit` to the tree, masters a plain ISO
        from it (no boot images: validation's GRUB check comes first), and
        makes the receipt name the result."""
        iso = self.out / media_operator.ISO
        tree = self.tmp / "tree"
        subprocess.run([media.tool("xorriso"), "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(tree)],
                       check=True, capture_output=True, env=media.clean_env(0))
        os.chmod(tree, 0o755)
        for root, dirs, files in os.walk(tree):
            for d in dirs:
                os.chmod(pathlib.Path(root) / d, 0o755)
            for f in files:
                os.chmod(pathlib.Path(root) / f, 0o644)
        edit(tree / "boot/grub")
        new = self.tmp / "new.iso"
        subprocess.run([media.tool("xorriso"), "-as", "mkisofs", "-quiet", "-R", "-J", "-o", str(new), str(tree)],
                       check=True, capture_output=True, env=media.clean_env(0))
        self.rename(new)

    def rename(self, new):
        iso = self.out / media_operator.ISO
        os.replace(new, iso)
        receipt = json.loads((self.out / media_operator.RECEIPT).read_text())
        receipt["artifacts"][media_operator.ISO].update(sha256=sha(iso), bytes=iso.stat().st_size)
        (self.out / media_operator.RECEIPT).write_text(json.dumps(receipt))

    def refused(self, text):
        with self.assertRaises(media.Refused) as caught:
            media_operator.operator_validate(type("Args", (), dict(
                profile="vm-operator", out=str(self.out), platform_tree=os.environ["ABSD_OPERATOR_PLATFORM"],
                kernel_run=os.environ["ABSD_OPERATOR_KERNEL"])))
        self.assertIn(text, str(caught.exception))

    def test_the_untampered_fixture_validates(self):
        media_operator.operator_validate(type("Args", (), dict(
            profile="vm-operator", out=str(self.out), platform_tree=os.environ["ABSD_OPERATOR_PLATFORM"],
            kernel_run=os.environ["ABSD_OPERATOR_KERNEL"])))

    def test_validate_refuses_an_unexpected_module(self):
        self.tamper(lambda grub: shutil.copyfile(self.extra, grub / "x86_64-efi/evil.mod"))
        self.refused("iso_grub_mismatch extra=['x86_64-efi/evil.mod']")

    def test_validate_refuses_a_missing_module(self):
        self.tamper(lambda grub: (grub / "i386-pc/moddep.lst").unlink())
        self.refused("missing=['i386-pc/moddep.lst']")

    def test_validate_refuses_a_changed_module(self):
        self.tamper(lambda grub: shutil.copyfile(self.extra, grub / "x86_64-efi/normal.mod"))
        self.refused("changed=['x86_64-efi/normal.mod']")

    def test_validate_refuses_an_unreadable_iso(self):
        truncated = self.tmp / "short.iso"
        truncated.write_bytes((self.out / media_operator.ISO).read_bytes()[:1 << 20])
        self.rename(truncated)
        self.refused("iso_unreadable")


class BootChecks(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("media_boot", here / "media_boot.py")
        self.mb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mb)

    def test_boot_checks_are_not_asserts(self):
        self.assertNotIn("assert ", (here / "media_boot.py").read_text())
        with self.assertRaises(self.mb.BootFailed):
            self.mb.require(False, "x")

    def test_qemu_paths_with_commas_are_refused(self):
        self.assertEqual(self.mb.qemu_path("/a/b.img"), "/a/b.img")
        with self.assertRaises(self.mb.BootFailed):
            self.mb.qemu_path("/a/b.img,format=qcow2")


class Profiles(unittest.TestCase):
    def test_unknown_profiles_are_refused_by_name(self):
        with self.assertRaises(media.Refused) as caught:
            media.load_profile("vm-nonesuch")
        self.assertIn("profile_not_implemented vm-nonesuch", str(caught.exception))

    def test_the_operator_profile_is_not_staged_as_a_usb_image(self):
        with self.assertRaises(media.Refused) as caught:
            media.stage(type("Args", (), dict(profile="vm-operator")))
        self.assertIn("profile_kind vm-operator is built with `media.py operator-image`", str(caught.exception))
        profile = media_operator.load_operator_profile("vm-operator")
        self.assertIn("durable=0 net fsd served", profile["expect"]["grub_entry"])
        self.assertEqual(profile["iso"]["locales"], "")
        for package in ("grub-pc-bin", "grub-efi-amd64-bin", "xorriso", "mtools", "faketime", "util-linux"):
            self.assertIn(package, profile["pins"]["packages"])
        with self.assertRaises(media.Refused):
            media_operator.load_operator_profile("z2-usb")

    def test_leading_comment_keeps_the_blank_line_after_it(self):
        self.assertEqual(media.leading_comment("/* a\n b */\n\nfn x() {}\n"), b"/* a\n b */\n\n")
        with self.assertRaises(media.Refused):
            media.leading_comment("fn x() {}\n")


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    if result.skipped and os.environ.get("ABSD_REQUIRE_S4") == "1":
        print(f"MEDIA HOST TEST FAILED: {len(result.skipped)} cases skipped with ABSD_REQUIRE_S4=1")
        for case, reason in result.skipped:
            print(f"  {case.id()}: {reason}")
        sys.exit(1)
    reasons = {}
    for case, reason in result.skipped:
        reasons[reason] = reasons.get(reason, 0) + 1
    for reason, count in sorted(reasons.items()):
        print(f"MEDIA HOST TEST SKIPPED {count}: {reason}")
    if result.wasSuccessful():
        print(f"MEDIA HOST TEST OK cases={result.testsRun} skipped={len(result.skipped)}")
    sys.exit(0 if result.wasSuccessful() else 1)
