#!/usr/bin/env python3
"""The original RC1 step-4 public-key blanking operation, with invariants.

This retains copy-on-write history, including the original public key in
unreferenced sectors. It is not a secure-erasure operation. No private key
is needed or shipped. Changing the initial public key changes raw disk bytes.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys


def main():
    top = Path(__file__).resolve().parents[1]
    work = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(top / "platform/scripts"))
    import operator_image as oi
    import absd_try
    blank = work / "blank"
    blank.mkdir(mode=0o700)
    image = blank / oi.IMAGE
    # Reserve the restrictive destination before copying disk contents.
    with image.open("xb") as dest:
        image.chmod(0o600)
        with (work / "media" / oi.IMAGE).open("rb") as source:
            shutil.copyfileobj(source, dest)
    shutil.copyfile(work / "media/MANIFEST", blank / "MANIFEST")
    before_sha = hashlib.sha256(image.read_bytes()).hexdigest()
    before = absd_try.read_state(image)
    importer_work = blank / "work"
    importer_work.mkdir()
    oi.import_boots(work / "kernel-aux", image, [(4, [(absd_try.KEYS_PATH, b"")])], importer_work,
                    qemu="qemu-system-x86_64 -accel tcg -cpu max,vendor=GenuineIntel,+rdrand", root=top / "platform")
    tree = absd_try.read_tree(image)
    rid = "absd-rc1-c12c-20261018t161241z.fvcgzh"
    absd_try.check_blank(tree, rid)
    oi.manifest_replace(blank, [(absd_try.KEYS_PATH, b"")])
    after = absd_try.read_state(image)
    if (before["fs_id"], before["format"]) != (after["fs_id"], after["format"]):
        raise SystemExit("blanking changed the filesystem identity")
    if after["seq"] <= before["seq"]:
        raise SystemExit("blanking did not advance the commit sequence")
    files = []
    for state in (before, after):
        files.append({p: o.get("sha256") for p, o in state["objects"].items()
                      if not o["dir"] and p != absd_try.KEYS_PATH})
    if files[0] != files[1]:
        raise SystemExit("blanking changed a file other than the public-key file")
    raw = image.read_bytes()
    public_body = (top / "docs/rc1/build-authorized-keys.pub").read_text().split()[1].encode()
    receipt = dict(release_id=rid, source_image_sha256=before_sha,
                   blank_sha256=hashlib.sha256(raw).hexdigest(), blank_bytes=len(raw),
                   seq=[before["seq"], after["seq"]], fs_id=after["fs_id"],
                   empty_authorized_keys=True, no_host_seed=absd_try.SEED_PATH not in tree,
                   public_key_residue_offsets=[m.start() for m in re.finditer(re.escape(public_body), raw)])
    (blank / "BLANK-DISK.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print("BLANK DISK OK " + json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
