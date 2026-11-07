#!/usr/bin/env python3
"""Producer smoke for the pre-enable window (#111 increment 6; oracle
interface v3.2 draft, `preenable`). QEMU waits for qtest before the CPU
runs; this script then plays a firmware-left bus master with a decoy edu at
00:<slot>.0: once firmware has given it a BAR, it keeps Bus Master Enable on
and fires 8-byte writes at a canary in rounds (snapshot AMD-Vi Control,
write the canary, fire, wait, read canary and Control) across the boot. It
checks that no write lands in a round that began with IommuEn set, that
writes stop after enable, and that ABSD lists the decoy in its
`AMDVI-ORACLE INHERITED` lines. It reports the pre-enable window as an
observation. Limits (weaker than the oracle's v3.2 leg): it waits for
firmware to assign the decoy's BAR and enable ECAM rather than starting
while QEMU is paused, so the first rounds begin some time after reset; it
samples rounds and cannot show denial at the IommuEn edge; a round whose DMA
never completes is counted as unjudged, not as denied. Usage:
  amdvi-preenable-smoke.py <iso> <out-dir> <qemu> <slot> [extra qemu args...]
"""
import os, re, socket, subprocess, sys, time
iso, out, qemu, slot, *extra = sys.argv[1:]
slot = int(slot, 16)
os.makedirs(out, exist_ok=True)
log = os.path.join(out, "serial.log"); sock = os.path.join(out, "qtest.sock")
for path in (log, sock):
    if os.path.exists(path): os.remove(path)
CANARY = 0x3FF0_0000  # near the top of 1 GiB: a page this smoke owns
MMIO = 0xFED80000
cmd = [qemu, "-M", "q35", "-accel", "tcg", "-smp", "1", "-m", "1024M", "-nic", "none",
       "-display", "none", "-monitor", "none", "-no-reboot", "-serial", f"file:{log}", *extra,
       "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-cdrom", iso,
       "-chardev", f"socket,id=qt,path={sock},server=on,wait=on", "-qtest", "chardev:qt"]
print("cmd:", " ".join(cmd), flush=True)
proc = subprocess.Popen(cmd, stdout=open(os.path.join(out, "qemu.out"), "w"),
                        stderr=open(os.path.join(out, "qemu.err"), "w"))
def serial():
    try: return open(log, "rb").read().decode(errors="replace").replace("\r\n", "\n")
    except FileNotFoundError: return ""
for _ in range(100):
    if os.path.exists(sock): break
    time.sleep(0.05)
qt = socket.socket(socket.AF_UNIX); qt.connect(sock); f = qt.makefile("rw")
def q(line):
    f.write(line + "\n"); f.flush()
    while True:
        r = f.readline().strip()
        if not r.startswith("IRQ"): return r
def rq(a): r = q(f"readq {a:#x}"); assert r.startswith("OK "), r; return int(r[3:], 16)
def rl(a): r = q(f"readl {a:#x}"); assert r.startswith("OK "), r; return int(r[3:], 16)
# Configuration space through ECAM (q35 MMCONFIG at 0xb0000000, set up by
# SeaBIOS), never ports 0xcf8/0xcfc, which the guest itself uses.
ECAM = 0xB0000000 + (slot << 15)
def cfg_read(off): return rl(ECAM + (off & 0xFFC))
def cfg_write(off, v): assert q(f"writel {ECAM + (off & 0xFFC):#x} {v:#x}") == "OK"
decoy_bme_after_ready = None
t0 = time.time(); rounds = []; first_bar = None; done_after = 0; violations = 0; unjudged = 0
try:
    while time.time() - t0 < 240 and proc.poll() is None:
        if first_bar is None:
            bar = cfg_read(0x10) & ~0xF
            if rl(0xB0000000) == 0xFFFFFFFF or cfg_read(0) != 0x11E81234 or bar in (0, 0xFFFFFFF0):
                time.sleep(0.01); continue
            first_bar = time.time() - t0
        bar = cfg_read(0x10) & ~0xF
        cfg_write(4, (cfg_read(4) & 0xFFFF) | 0x6)
        en0 = rq(MMIO + 0x18) & 1
        marker = 0x5EED_0000_0000_0000 | len(rounds)
        assert q(f"writeq {CANARY:#x} {marker:#x}") == "OK"
        for off, v in ((0x80, 0x40000), (0x88, CANARY), (0x90, 8)):
            assert q(f"writeq {bar + off:#x} {v:#x}") == "OK"
        assert q(f"writeq {bar + 0x98:#x} 0x3") == "OK"
        deadline = time.time() + 5
        while rq(bar + 0x98) & 1 and time.time() < deadline: time.sleep(0.005)
        completed = not (rq(bar + 0x98) & 1)
        landed = rq(CANARY) != marker
        en1 = rq(MMIO + 0x18) & 1
        if not completed:
            # The DMA never completed: not judged (neither landed nor denied).
            unjudged += 1
            continue
        rounds.append((round(time.time() - t0, 3), en0, en1, landed))
        if en0 and landed: violations += 1
        if en0:
            done_after += 1
            if done_after >= 20: break
    ready = None
    last_force = time.time()
    for _ in range(600):
        if re.search(r"^AMDVI-ORACLE READY$", serial(), re.M): ready = True; break
        if proc.poll() is not None: break
        time.sleep(0.2)
    # The decoy is the oracle's: on the enforced path ABSD must not clear its
    # Bus Master Enable (it was last forced on before the final round).
    decoy_bme_after_ready = bool(cfg_read(4) & 0x4) if ready else None
finally:
    text = serial()
    if proc.poll() is None: proc.kill(); proc.wait()
decoy = (0 << 8) | (slot << 3)
inherited = [int(x, 16) for x in re.findall(r"^AMDVI-ORACLE INHERITED devid=(0x[0-9a-f]+) bme=1$", text, re.M)]
pre = [r for r in rounds if not r[1]]
post = [r for r in rounds if r[1]]
first_en = next((r[0] for r in rounds if r[1]), None)
print(f"preenable: first-bar-s={first_bar} unjudged={unjudged} rounds={len(rounds)} pre-enable={len(pre)} landed-pre={sum(r[3] for r in pre)} post-enable={len(post)} landed-post={sum(r[3] for r in post)} first-enable-observed-s={first_en}")
print(f"preenable: inherited={[hex(i) for i in inherited]} decoy={decoy:#x} disclosed={decoy in inherited} ready={ready} decoy-bme-after-ready={decoy_bme_after_ready}")
for line in re.findall(r"^(AMDVI PREENABLE-WINDOW .*|AMDVI INHERITED .*|DMA INHERITED .*)$", text, re.M): print("serial:", line)
open(os.path.join(out, "rounds.txt"), "w").write("\n".join(f"{t} en0={a} en1={b} landed={int(c)}" for t, a, b, c in rounds) + "\n")
# Success needs the intended 20 completed enabled-start rounds and a
# pre-enable landing witness (the decoy really was mastering before enable).
ok = (violations == 0 and len(post) >= 20 and not any(r[3] for r in post)
      and any(r[3] for r in pre) and decoy in inherited and ready and decoy_bme_after_ready)
print("preenable:", "OK" if ok else f"FAILED violations={violations}")
sys.exit(0 if ok else 1)
