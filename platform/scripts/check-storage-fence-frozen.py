#!/usr/bin/env python3
"""Check the frozen-harness source boundary of ACCEPTANCE-v5 (coordination record #63).

The guest helper, the reviewed #94/#119 files and the SSH helper have exact
whole-file Git blob pins. Their old base versions are not current admissible sources.
Other files retain their historical per-line diff allowances against the base;
those allowances do not establish exact patch structure or runtime consumption.

  python3 -I scripts/check-storage-fence-frozen.py [--base 0414342f]

Prints `STORAGE FENCE FROZEN OK files=<n>` and exits 0, or names pinned
source mismatches and lines outside historical allowances and exits 1.
"""

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = "0414342f"
GUEST_BLOB = "c5b0621d9a7ae82bd8f41411eff429a194348121"
# Current reviewed sources: whole-file identity preserves required lines,
# occurrence counts, order and context. Base versions lack required controls.
# Steward Claude git-0a, 2026-11-05 21:58Z: accepted logging build arguments
# LOGD_ELF and LOGD_FAULT=0 in ServedTarget.iso and AbsdTarget.iso.
# Exact whole-file disposition, including the preceding SFTP comment review:
# archived-runs/integration-steward-20261011/outbox/
# 20261105T2158Z-steward-frozen-pins-codex-01a1aa64.md
# SHA256 b8b2a16241434f4cdc513b79d5eae805e525f40bad08b9cde8fb1a0c5f325ac2.
# PTY oracle review: steward Claude git-0a, 2026-11-06 01:34Z.
# outbox/20261106T0133Z-steward-paste-oracle-accept-01a1aa59.md
# Patch SHA256 01bb61f97a9eb59aad45fc9511bb3db790e5e5e8d89c392a629e4ea56afd02f3.
# Only live PTY mode bytes changed; historical frozen fixtures stay pinned.
# Combined LOGD + PTY blobs accepted by steward git-0a, 2026-11-06 01:41Z:
# outbox/20261106T0141Z-steward-combined-blobs-accept-01a1aa64.md
# COMBINED-LIVE-BLOBS.patch SHA256 081bc4003474b2bf2c08af2a62a2a73be67991cb5165b0a7260495529872a9da.
# Capacity/profile oracle review: Claude git-0a, 2026-11-06.
# CAPACITY-INDEPENDENT-REVIEW-claude-git0a.md SHA256
# a48e6380453e30ea0974c303a0f7d67be42c9ef2bd0d7e2ba9c91c88c8fdf400.
# Only the two exact reviewed live blobs advance; historical fixtures stay pinned.
# Journal inventory oracle: Claude git-0a ACCEPT, 2026-11-06.
# journal-oracle01/INDEPENDENT-REVIEW-claude-git0a.md SHA256
# 7ee5ba1f3bfa6f41e28e2465e9a6f250c68973125a9fd393c663f93c9eadaa66.
# Exact ssh_absd live blob only; historical fixtures remain unchanged.
REVIEWED_BLOBS = {
    "scripts/run-storage-fence-matrix.sh": "c99193d372c8206cafc8661bd87db685e05bf73d",
    "scripts/storage-fence-ghost.py": "068e9d3e34a6bcb252c4f741596ce8ecdf1b9575",
    # Served-only prompt-context repair: steward Claude git-0a, 2026-11-06 01:53Z.
    # outbox/20261106T0153Z-steward-oracle02-accept-01a1aa59.md
    # Patch SHA256 e38fba546a61f64969dc765f75a3b1b90851840d923febad7617dc0843c16aff.
    # Combined LOGD + oracle02 blob accepted by steward git-0a, 2026-11-06 01:57Z.
    # outbox/20261106T0157Z-steward-combined-blob02-accept-01a1aa64.md
    # Combined patch SHA256 a13acea45de63e8a1b2d682ec9e22e8f57ba9ea9ceb0ae4152d20c46fe99c90c.
    "scripts/served-matrix.py": "103107ec8f9ad713803c0dd1795a831fa3ba19e8",
    # Same PTY oracle review; the earlier SFTP disposition stays historical.
    # Exact eight-mount oracle accepted by steward Claude git-0a, 2026-11-06 03:06Z.
    # outbox/20261106T0306Z-steward-mount-oracle-accept-01a1aa64.md
    # Acceptance record SHA256 eb847dee6010c10f19c874753ee701e5d7a2877ebe87150c860107478d5497ba.
    "scripts/ssh_absd.py": "56bf45d31994c8836326eac28f04e8fc6a1b3e49",
}
UNSUPPORTED = 'AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act only)'

# File -> list of regexes; every added or removed line of its diff must
# match one of them (an empty list: no change at all).
FROZEN = {
    "scripts/storage_fence_guest.py": [],
    "scripts/storage-fence-matrix.py": [],
    "scripts/core-fsd-recovery.py": [],
    "scripts/storage-fence-updates.py": [],
    "scripts/served_ram.py": [],
    "scripts/absd_fs.py": [],
    "scripts/storage_fence_host.py": [],
    "scripts/e1000_rx.py": [],
    "scripts/storage-fence-upgrade.py": [],
    "scripts/storage_fence_upgrade.py": [
        # (1) entries gains the slot; (2) content comparison widened;
        # (3) namespace comparison widened; (4) the source refusal names the slot.
        r"^[-+]\s+entries = \[\(guard\.PATH, guard\.encode\('clean'\)\)(, \(guard\.RESUME_PATH, guard\.encode_resume\('none'\)\))?\]$",
        r"^[-+]\s+if found_tree != dict\(tree, \*\*\{guard\.PATH: guard\.encode\('clean'\)(, guard\.RESUME_PATH: guard\.encode_resume\('none'\))?\}\):$",
        r"^[-+]\s+if set\(found_namespace\) != set\(old_namespace\) \| \{guard\.PATH(, guard\.RESUME_PATH)?\}:$",
        r"^[-+]\s+if guard\.PATH in tree( or guard\.RESUME_PATH in tree)?:$",
        r"^[-+]\s+raise ValueError\('clean evidence: guard (already exists|or resume slot already exists); conversion never resets it'\)$",
        r"^[-+]\s+if guard\.PATH in old_namespace or any\(p == '/var/state\.new' or p\.startswith\('/var/state\.new/'\)$",
        r"^[-+]\s+for p in old_namespace\):$",
        r"^[-+]\s+if \(guard\.PATH in old_namespace or guard\.RESUME_PATH in old_namespace$",
        r"^[-+]\s+or any\(p == '/var/state\.new' or p\.startswith\('/var/state\.new/'\) for p in old_namespace\)\):$",
        r"^[-+]\s+raise ValueError\('clean evidence: existing guard(, resume slot)? or incomplete recovery staging'\)$",
    ],
    "scripts/survival-recovery.py": [
        r"^\+# .*$",  # the comment above the local constant
        r"^\+UNSUPPORTED = \"" + re.escape(UNSUPPORTED) + r"\"$",
        r"^[-+]\s+line = f\"\{(fence_guest\.)?UNSUPPORTED\} case=\{case\} \{detail\}\"$",
    ],
    "scripts/link-matrix.py": [
        r"^-UNSUPPORTED = fence_guest\.UNSUPPORTED$",
        r"^\+UNSUPPORTED = \"" + re.escape(UNSUPPORTED) + r"\"$",
    ],
    "scripts/health-json-native.py": [
        r"^-follow-on cases\) are observed; WRITABLE RECOVERY UNSUPPORTED is inherited\.$",
        r"^\+follow-on cases\) are observed; AUTOMATIC WRITABLE RECOVERY UNSUPPORTED \(the$",
        r"^\+operator act of coordination record #63 is the only writable recovery\) is inherited\.$",
    ],
    "scripts/test_survival_fence.py": [
        r"^[-+]\s+self\.assertTrue\(line\.startswith\(\".*WRITABLE RECOVERY UNSUPPORTED.* case=sshd:fault-loop\"\)\)$",
        r"^[-+]\s+lines = text\.split\(\".*WRITABLE RECOVERY UNSUPPORTED.*\"\)$",
    ],
    "scripts/test_link_matrix.py": [
        r"^[-+]\s+self\.assertIn\(\".*WRITABLE RECOVERY UNSUPPORTED.* case=disabled-nic-budget\", unsupported\[0\]\)$",
    ],
}
# Files allowed to change freely under the rule (listed for the record).
OPEN = ("scripts/storage_fence_state.py", "scripts/model-storage-fence.py")


def diff_lines(base, path):
    text = subprocess.run(["git", "-C", str(ROOT), "diff", base, "--", path], check=True, capture_output=True,
                          text=True).stdout
    return [line for line in text.splitlines()
            if (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---"))]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args(argv)
    problems = []
    blob = subprocess.run(["git", "-C", str(ROOT), "hash-object", "scripts/storage_fence_guest.py"], check=True,
                          capture_output=True, text=True).stdout.strip()
    if blob != GUEST_BLOB:
        problems.append(f"scripts/storage_fence_guest.py: blob {blob} is not the pinned {GUEST_BLOB}")
    for path, pinned in REVIEWED_BLOBS.items():
        result = subprocess.run(["git", "-C", str(ROOT), "hash-object", "--no-filters", path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            problems.append(f"{path}: cannot hash pinned source")
        elif result.stdout.strip() != pinned:
            problems.append(f"{path}: blob {result.stdout.strip()} is not the pinned {pinned}")
    adversarial = diff_lines(args.base, "qual/adversarial")
    if adversarial:
        problems.append(f"qual/adversarial: {len(adversarial)} changed lines")
    for path, allowed in FROZEN.items():
        for line in diff_lines(args.base, path):
            if not any(re.match(pattern, line) for pattern in allowed):
                problems.append(f"{path}: {line}")
    if problems:
        print("STORAGE FENCE FROZEN FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print(f"STORAGE FENCE FROZEN OK files={len(FROZEN) + len(REVIEWED_BLOBS) + 1} base={args.base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
