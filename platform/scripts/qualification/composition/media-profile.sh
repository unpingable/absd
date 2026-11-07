#!/bin/sh
# Preserve the full vm-operator profile producer, validator and 74/0 fixture suite.
set -eu
W=${ABSD_COMPOSITION_PLATFORM:?clean final candidate required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
K=${ABSD_COMPOSITION_PROFILE_KERNEL:?fresh dedicated profile kernel checkout required}
REV=${ABSD_COMPOSITION_SOURCE_REVISION:?exact source revision required}
KREV=${ABSD_COMPOSITION_KERNEL_COMMIT:?exact kernel revision required}
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
INPUTS=${ABSD_COMPOSITION_PROFILE_BOOT_INPUTS:?prepared bound importer inputs required}
PIN=${ABSD_COMPOSITION_PROFILE_BOOT_INPUTS_SHA256:?independent input pin required}
OUT=$G/work/media-profile
! test -e "$OUT"
"$G/tools/gate.sh" "$G/logs/load-gate.log" media-profile-image
python3 -I -B "$W/scripts/media.py" operator-image --profile vm-operator --platform-tree "$W" --kernel-run "$K" --platform-commit "$REV" --kernel-commit "$KREV" --authorized-keys "$KEY.pub" --bound-boot-inputs "$INPUTS" --bound-boot-inputs-sha256 "$PIN" --out "$OUT" > "$G/logs/media-profile-image.log" 2>&1
python3 -I -B "$W/scripts/media.py" operator-validate --profile vm-operator --platform-tree "$W" --kernel-run "$K" --out "$OUT" > "$G/logs/media-profile-validate.log" 2>&1
ABSD_MEDIA_E2E=1 ABSD_REQUIRE_S4=1 ABSD_OPERATOR_FIXTURE="$OUT" ABSD_OPERATOR_PLATFORM="$W" ABSD_OPERATOR_KERNEL="$K" ABSD_U1B_IMAGE="$OUT/absd-operator.img" python3 -I -B "$W/scripts/test_media.py" > "$G/logs/media-profile-tests.log" 2>&1
grep -qx 'MEDIA HOST TEST OK cases=74 skipped=0' "$G/logs/media-profile-tests.log"
census=$("$G/tools/gate.sh" --list)
if printf '%s\n' "$census" | grep -q '^other'; then
  printf '%s\n' "$census" >&2
  exit 1
fi
