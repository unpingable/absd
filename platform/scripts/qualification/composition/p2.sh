#!/bin/sh
# Existing P00-P08 oracle, actual A/B ELF difference, canonical bound launches.
set -eu
W=${ABSD_COMPOSITION_PLATFORM:?clean final candidate required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
Q=${ABSD_COMPOSITION_QEMU:?absolute admitted QEMU executable required}
QP=${ABSD_COMPOSITION_QEMU_SHA256:?independent executable pin required}
A=${ABSD_COMPOSITION_P2_A:?complete pinned internal baseline release required}
B=${ABSD_COMPOSITION_P2_B:?complete final candidate release required}
AP=${ABSD_COMPOSITION_P2_A_MANIFEST_SHA256:?independent A manifest pin required}
BP=${ABSD_COMPOSITION_P2_B_MANIFEST_SHA256:?independent B manifest pin required}
REV=${ABSD_COMPOSITION_SOURCE_REVISION:?exact final candidate revision required}
ANC=${ABSD_COMPOSITION_P2_ANCESTRY:?A-to-B ancestry receipt required}
ANCP=${ABSD_COMPOSITION_P2_ANCESTRY_SHA256:?independent ancestry pin required}
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
"$G/tools/gate.sh" "$G/logs/load-gate.log" p2
unset ABSD_QEMU_REBOOT
ABSD_BLOCK_ATTACH=ata ABSD_RELEASE_QEMU="$Q -accel tcg -cpu max,vendor=GenuineIntel,+rdrand" python3 -I -B "$W/scripts/recovery-point-matrix.py" \
  --release-a "$A" --release-b "$B" --source-a 03479a3e090e847ccdfa647dce44e7b16d035988 --source-b "$REV" \
  --ancestry "$ANC" --ancestry-sha256 "$ANCP" --kernel "$G/work/KA" --key "$KEY" \
  --private-work "$G/work/p2-private" --evidence "$G/p2-evidence" \
  --require-binary-change tree/bin/https-document --bound-qemu "$Q" --bound-qemu-sha256 "$QP" \
  --release-a-manifest-sha256 "$AP" --release-b-manifest-sha256 "$BP" > "$G/logs/p2.log" 2>&1
census=$("$G/tools/gate.sh" --list)
if printf '%s\n' "$census" | grep -q '^other'; then
  printf '%s\n' "$census" >&2
  exit 1
fi
