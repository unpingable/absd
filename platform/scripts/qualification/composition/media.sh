#!/bin/sh
# Execute the existing full artifact-bound media producer and boot.
set -eu
W=${ABSD_COMPOSITION_PLATFORM:?clean final candidate required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
K=${ABSD_COMPOSITION_MEDIA_KERNEL:?fresh dedicated media kernel checkout required}
REV=${ABSD_COMPOSITION_KERNEL_COMMIT:?exact kernel revision required}
Q=${ABSD_COMPOSITION_QEMU:?absolute admitted QEMU executable required}
BUILD=${ABSD_COMPOSITION_BUILD_RECEIPT:?successful exact platform build receipt required}
PIN=${ABSD_COMPOSITION_BUILD_RECEIPT_SHA256:?independent build receipt pin required}
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
OUT=$G/work/media
RESULTS=$G/media-results
STATUS=${ABSD_COMPOSITION_MEDIA_STATUS:?fresh media status path required}
test "${ABSD_HTTPS_DOCUMENT:-0}" = 1
! test -e "$OUT"
! test -e "$RESULTS"
! test -e "$STATUS"
"$G/tools/gate.sh" "$G/logs/load-gate.log" media-build
python3 -I "$W/scripts/qualify-operator-binding.py" build --kernel "$K" --kernel-commit "$REV" --out "$OUT" --qemu "$Q" --build-receipt "$BUILD" --build-receipt-sha256 "$PIN" --authorized-keys "$KEY.pub" > "$G/logs/media-build.log" 2>&1
BIND=$(sha256sum "$OUT/BOOT-BINDING.json")
BIND=${BIND%% *}
"$G/tools/gate.sh" "$G/logs/load-gate.log" media-boot
python3 -I "$W/scripts/qualify-operator-binding.py" boot --kernel "$K" --out "$OUT" --qemu "$Q" --build-receipt "$BUILD" --build-receipt-sha256 "$PIN" --binding-sha256 "$BIND" --login-key "$KEY" --results "$RESULTS" > "$G/logs/media-boot.log" 2>&1
# Preserve the existing MUST interface, deriving it only from actual receipts.
python3 -I "$W/scripts/qualify-operator-binding.py" status --kernel "$K" --out "$OUT" --qemu "$Q" --build-receipt "$BUILD" --build-receipt-sha256 "$PIN" --binding-sha256 "$BIND" --results "$RESULTS" > "$G/logs/media-status-check.log" 2>&1
test "$(cat "$G/logs/media-status-check.log")" = PASS
census=$("$G/tools/gate.sh" --list)
if printf '%s\n' "$census" | grep -q '^other'; then
  printf '%s\n' "$census" >&2
  exit 1
fi
(set -C; printf 'PASS\n' > "$STATUS")
