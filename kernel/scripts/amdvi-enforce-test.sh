#!/bin/sh
# AMD-Vi enforce test (#111 increment 3) on q35 + amd-iommu + edu (TCG).
# Producer self-check only: ABSD's serial lines are claims; the independent
# oracle (separate lane) judges DMA outcomes. Needs QEMU whose generated
# IVRS the backend admits (QEMU=/usr/bin/qemu-system-x86_64 10.2.1 on
# execution_host), with dma-remap=on: without it QEMU 10.2.1 never translates
# an emulated function's DMA, and with it a function is translated only
# after its entry is invalidated while it has TV=0 or Mode != 0: a V=1 TV=1
# Mode=0 entry is passed through even with IR=IW=0. ABSD's blocked entries
# are therefore V=1 TV=0 IR=IW=0, and it invalidates every DeviceID's entry
# after enabling the unit.
# EXPECT=ahci (#123; ISO from `make amdvi-enforce-ahci-iso`, boot line
# `amdvi-enforce-test ahci-disk=absd`): also attaches an ich9-ahci
# controller at 00:07.0 with one ide-hd (serial absd) on a fixture image
# (snapshot=on: QEMU's ide-hd refuses a read-only drive; the fixture's hash
# is checked after the run), and checks the AHCI self-check and the
# EVIDENCE DIGEST line (scripts/evidence-digest.py) as well as every edu
# line.
# Exit: 0 when the boot reports ENFORCE OK and every expected record is
# present.
set -eu
iso=$1
QEMU=${QEMU:-qemu-system-x86_64}
out=build/amdvi-enforce${EXPECT:+-$EXPECT}
rm -rf "$out"; mkdir -p "$out"
die() { echo "amdvi-enforce-test: $*" >&2; exit 1; }
# QEMU may be a wrapper whose own stdout does not reach us (execution_host's
# vm-admit sends the guest's to the journal): QEMU_PROBE names the binary
# to ask for its version. An empty answer fails the run.
probe_out=$(${QEMU_PROBE:-$QEMU} --version) || die "QEMU version probe ${QEMU_PROBE:-$QEMU} failed"
version=$(printf '%s\n' "$probe_out" | head -1)
case $version in "QEMU emulator version "*) ;; *) die "no QEMU version from ${QEMU_PROBE:-$QEMU} --version (set QEMU_PROBE)" ;; esac
printf '%s\n' "$version" | tee "$out/qemu-version.txt"
sha256sum "$iso" | tee "$out/iso.sha256"
log=$out/serial.log
status=0
ahci_args=
if [ "${EXPECT:-admit}" = ahci ]; then
	fixture=$out/fixture.img
	python3 -c 'import hashlib, sys
with open(sys.argv[1], "wb") as image:
    for lba in range(2048):
        image.write((hashlib.sha256(b"absd116-lba-%d" % lba).digest() * 16)[:512])' "$fixture"
	fixture_sha=$(sha256sum "$fixture" | cut -d" " -f1)
	ahci_args="-boot d -device ich9-ahci,id=ahci7,addr=0x7 -drive if=none,id=sata7,file=$fixture,format=raw,snapshot=on -device ide-hd,bus=ahci7.0,serial=absd,drive=sata7"
fi
timeout 300s $QEMU -M q35 -accel tcg -m 512M -smp 1 -cdrom "$iso" -display none \
	-device amd-iommu${IOMMU_OPTIONS-,dma-remap=on} -device edu,addr=5 $ahci_args ${QEMU_EXTRA:-} \
	-serial file:"$log" -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
	>"$out/qemu.out" 2>"$out/qemu.err" || status=$?
echo "amdvi-enforce-test: qemu exit $status"
grep '^AMDVI \|^DMA \|^AHCI \|^EVIDENCE ' "$log" || true
if grep -q 'PANIC\|KERNEL FAULT' "$log"; then die "kernel fault"; fi
if [ "${EXPECT:-admit}" = refuse-efrsup ]; then
	# Run with IOMMU_OPTIONS= (QEMU 8.2.2 has no dma-remap property).
	# QEMU 8.2.2: IVinfo EFRSup=0 against the capability header's EFRSup=1.
	grep -qx 'AMDVI ENFORCE REFUSED stage=admit-table reason=EfrSupMismatch' "$log" || die "8.2.2 table not refused on EFRSup"
	if grep -q '^AMDVI \(ENABLED\|CONTAINED\|GRANT\)\|^DMA ARM' "$log"; then die "refused table still enabled something"; fi
	# Refusal path: inherited masters closed, R2 only (increment 6 split).
	grep -q '^AMDVI INHERITED-BME closed=[0-9]* path=refusal step=R2 claims=none$' "$log" || die "refusal path did not close inherited masters"
	grep -q '^AMDVI INHERITED count=[0-9]* after-enable=not-contained (enforcement unavailable)$' "$log" || die "refusal path did not report inherited masters"
	echo "amdvi-enforce-test: refused as expected ($log)"
	exit 0
fi
grep -q '^AMDVI ADMIT table=ok deviations=1 quirked=1$' "$log" || die "table not admitted under the quirk"
grep -q '^AMDVI QUIRK name=qemu-superseded-10h-hats version=1 block=10h ' "$log" || die "quirk not reported"
grep -q '^AMDVI ADMIT device=00:05.0 closure=own-only$' "$log" || die "edu not admitted"
grep -q '^AMDVI COMPLETION step=invalidate expected=\(0x[0-9a-f]*\) observed=\1 result=ok$' "$log" || die "no completion read back"
grep -q '^AMDVI CONTAINED devid=00:05.0 domain=1 bme=on profile=enforced$' "$log" || die "not contained"
grep -q '^AMDVI SELFCHECK permitted read=done write=done payload=match$' "$log" || die "permitted transfer"
grep -q '^AMDVI SELFCHECK forbidden device=done canary=intact read-only-page=intact$' "$log" || die "forbidden write landed"
grep -q '^AMDVI SELFCHECK events=[1-9][0-9]* io-page-faults-from-target=[1-9][0-9]* overflow=no$' "$log" || die "no fault event from the target"
# Increments 4-5: revocation R1-R5 and claims, restart onto set 2,
# exhaustion, failed unit.
grep -q '^AMDVI REVOKE devid=00:05.0 R1=closed R2=bme-clear R3=completed R4=reset-unavailable R5=no-mechanism$' "$log" || die "revocation steps"
grep -q '^AMDVI CLAIM devid=00:05.0 contained=ESTABLISHED$' "$log" || die "contained not established"
grep -q '^AMDVI CLAIM devid=00:05.0 settled=UNESTABLISHED$' "$log" || die "settled claimed"
grep -q '^AMDVI CLAIM devid=00:05.0 reclaimable=UNESTABLISHED$' "$log" || die "reclaimable claimed"
if grep -q '^AMDVI CLAIM .*\(settled\|reclaimable\)=ESTABLISHED' "$log"; then die "settlement claimed"; fi
[ "$(grep -c '^DMA RETAINED owner=edu set=[12] .* custodian=dma release=never' "$log")" = 2 ] || die "sets not retained"
grep -q '^AMDVI LIFETIME restart=set2 set2-transfer=match retained-set1-write=blocked$' "$log" || die "restart onto set 2"
grep -q '^AMDVI LIFETIME second-restart=CONTAINED_BUT_UNUSABLE unusable=CONTAINED_BUT_UNUSABLE$' "$log" || die "exhaustion"
grep -q '^AMDVI UNIT FAILED reason=illegal-command devid=00:05.0 bme=clear step=R2 claims=none$' "$log" || die "illegal command did not fail the unit"
grep -q '^AMDVI LIFETIME unit=illegal-command restart-after-failure=unit-failed bme=clear$' "$log" || die "failed unit still restarts"
# Increment 6: the pre-enable window, inherited masters reported after
# enable and left untouched (blocked by the unit, not by clearing BME).
grep -q '^AMDVI PREENABLE-WINDOW kernel-main-to-iommu-en-cycles=[0-9]* kernel-main-to-deny-by-default-cycles=[0-9]* tsc-rate=unmeasured ' "$log" || die "no pre-enable window"
# Inherited masters that are translated targets (the AHCI here) are counted
# apart: only the others are blocked and untouched.
targets=0; [ "${EXPECT:-admit}" = ahci ] && targets=1
grep -q "^AMDVI INHERITED count=[0-9]* translated-targets=$targets after-enable=others-blocked-whatever-bme others-bme=unchanged\$" "$log" || die "inherited masters not reported (translated-targets=$targets)"
grep -q '^DMA INHERITED total=[0-9]*' "$log" || die "no inherited list"
if grep -q '^AMDVI INHERITED-BME closed=' "$log"; then die "inherited masters closed in the enforced path"; fi
# Increment 7: the one interrupt grant (index 0x10, vector 0x41, remapped).
grep -q '^AMDVI IRGRANT devid=00:05.0 index=0x10 vector=0x41 dest=0x[0-9a-f]* table=0x[0-9a-f]* entries=512 intctl=remap$' "$log" || die "no interrupt grant"
grep -qx 'AMDVI ENFORCE OK' "$log" || die "no ENFORCE OK"
if [ "${EXPECT:-admit}" = ahci ]; then
	# #123: the AHCI controller at 00:07.0 in its own domain, only its
	# static pages granted, with per-role permissions.
	grep -q '^AMDVI ADMIT device=00:07.0 closure=own-only driver=ahci$' "$log" || die "AHCI not admitted"
	grep -q '^AMDVI DOMAIN id=2 devid=00:07.0 mode=3 root=0x[0-9a-f]* ir-table=0x[0-9a-f]* interrupts=deny-all$' "$log" || die "no AHCI domain"
	for role in cl:rw fis:rw ctba:r bounce:rw; do
		grep -q "^AMDVI GRANT devid=00:07.0 iova=0x[0-9a-f]* page=0x[0-9a-f]* bytes=4096 perm=${role#*:} role=${role%:*}\$" "$log" || die "no AHCI grant $role"
	done
	[ "$(grep -c '^AMDVI GRANT devid=00:07.0 ' "$log")" = 4 ] || die "AHCI grant is not exactly four pages"
	grep -q '^AMDVI TIMER pit-ticks=[0-9]* purpose=ahci-driver$' "$log" || die "no timer for the AHCI driver"
	grep -q '^AMDVI CONTAINED devid=00:07.0 domain=2 bme=on profile=enforced driver=ahci$' "$log" || die "AHCI not contained"
	grep -q '^AHCI DISK pci=00:07.0 port=0 serial="absd" model="QEMU HARDDISK" selected=yes$' "$log" || die "AHCI disk not selected"
	# Its own DMA only: q35's built-in controller (00:1f.2) is never probed.
	if grep -q '^AHCI \(DISK\|CONTROLLER\) pci=00:1f.2' "$log"; then die "built-in AHCI controller probed"; fi
	want=$(python3 -c 'import hashlib
data = (hashlib.sha256(b"absd116-lba-0").digest() * 16)[:512]
h = 0xcbf29ce484222325
for b in data:
    h = ((h ^ b) * 0x100000001b3) & 0xffffffffffffffff
print("%#018x" % h)')
	grep -q "^AMDVI AHCI permitted lba=0 read=done fnv1a=$want\$" "$log" || die "permitted AHCI read (want fnv1a=$want)"
	grep -q '^AMDVI AHCI forbidden dba=0x[0-9a-f]* status=done canary=unchanged io-page-faults-from-target=[1-9][0-9]* liveness=ok$' "$log" || die "forbidden AHCI read not done, landed, faulted nothing or broke the port"
	grep -q '^AMDVI AHCI REVOKED r3=completed later-read=refused bme=clear contained-registry=released$' "$log" || die "AHCI revocation"
	[ "$(grep -c '^AHCI PORT WITHDRAWN reason=revoke$' "$log")" = 2 ] || die "AHCI R1 withdrawals"
	[ "$(grep -c '^AHCI PORT CLEANUP stop=confirmed dma=off$' "$log")" = 2 ] || die "AHCI R4 stops"
	[ "$(grep -c '^AMDVI REVOKE devid=00:07.0 R1=closed R2=bme-clear R3=completed R4=reset-requested-stop-confirmed R5=no-mechanism$' "$log")" = 2 ] || die "AHCI revocation steps"
	grep -q '^AMDVI CLAIM devid=00:07.0 contained=ESTABLISHED$' "$log" || die "AHCI contained not established"
	[ "$(grep -c '^DMA RETAINED owner=ahci set=[12] .* custodian=dma release=never' "$log")" = 2 ] || die "AHCI sets not retained"
	grep -q '^AMDVI AHCI LIFETIME restart=set2 read=match retained-set1=unchanged retained-status=done retained-faults=[1-9][0-9]* after=match second-restart=CONTAINED_BUT_UNUSABLE$' "$log" || die "AHCI lifetime"
	grep -q '^AMDVI UNIT FAILED reason=illegal-command devid=00:07.0 bme=clear step=R2 claims=none$' "$log" || die "failed unit left the AHCI armed"
	grep -q '^EVIDENCE DIGEST bytes=[0-9]* fnv1a=[0-9a-f]\{16\} tx-dropped=0$' "$log" || die "no evidence digest"
	python3 scripts/evidence-digest.py "$log" || die "evidence digest does not match the log"
	[ "$(sha256sum "$fixture" | cut -d" " -f1)" = "$fixture_sha" ] || die "fixture image changed"
elif grep -q '^AMDVI ADMIT device=00:07.0 \|^EVIDENCE ' "$log"; then
	die "AHCI target or evidence line without ahci-disk="
fi
echo "amdvi-enforce-test: producer self-check passed ($log)"
