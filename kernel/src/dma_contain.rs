//! The `dma-contain=` boot word (#111, #123 step 2; design:
//! docs/superpowers/specs/2026-11-04-amdvi-operator-design.md section 4).
//! Pure: what the word names and which other boot words it cannot run with.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Word {
    pub ahci: Option<Bdf>,
    pub rtl8125: Option<Bdf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordRefusal {
    Empty,
    UnknownDriver,
    Address,
    DuplicateDriver,
    SameFunction,
    Conflict,
    NeedsDisk,
    NeedsNetBackend,
    NeedsNetProbe,
    CheckNeedsDisk,
}

impl Word {
    /// `dma-contain=none`: the unit comes up with nothing armed.
    pub fn is_census(&self) -> bool {
        self.ahci.is_none() && self.rtl8125.is_none()
    }
}

impl WordRefusal {
    pub fn word(self) -> &'static str {
        match self {
            WordRefusal::Empty => "empty",
            WordRefusal::UnknownDriver => "unknown-driver",
            WordRefusal::Address => "address",
            WordRefusal::DuplicateDriver => "duplicate-driver",
            WordRefusal::SameFunction => "same-function",
            WordRefusal::Conflict => "conflict",
            WordRefusal::NeedsDisk => "needs-ahci-disk",
            WordRefusal::NeedsNetBackend => "needs-net-rtl8125",
            WordRefusal::NeedsNetProbe => "needs-net",
            WordRefusal::CheckNeedsDisk => "check-needs-ahci",
        }
    }
}

/// Boot words that run with `dma-contain`. Everything else in src/main.rs is
/// in [`REFUSED_WORDS`]; a host test fails on a word in neither.
pub const COMPATIBLE_WORDS: &[&[u8]] = &[
    b"acpi",
    b"acpi-poweroff",
    b"acpi-reset-qemu",
    b"ahci-disk=",
    b"ahci-write=",
    b"block-partition=",
    b"block-probe",
    b"dma-contain-census-seconds=",
    b"dma-contain-check",
    b"dma-contain-inject=",
    b"dma-contain=",
    b"dma-report",
    b"durable=",
    b"external",
    b"external-live",
    b"fsd",
    b"halt-on-exit",
    b"net",
    b"net-probe",
    b"net-rtl8125",
    b"rtl8125-no-phy-tuning",
    b"served",
    b"shell",
    b"storage-fence=",
];

/// Boot words that reach a device outside the named targets, or are
/// qualification modes this path does not support. Some are values of other
/// options rather than words of their own; refusing those is harmless.
pub const REFUSED_WORDS: &[&[u8]] = &[
    b"acpi-test",
    b"ahci-census",
    b"ahci-census-pretend-raid",
    b"ahci-census-pretend-stuck-stop",
    b"ahci-pretend-decode-off",
    b"ahci-pretend-pending=",
    b"amdvi-enforce-test",
    b"amdvi-oracle=1",
    b"block-partition-qualify",
    b"bsp-refusal-test",
    b"cpu-identity-alias",
    b"cpu-identity-uninitialized",
    b"cpu-identity-wrong-id",
    b"enumeration-hold",
    b"fault-test",
    b"fpu-test",
    b"fuzz",
    b"handoff-negative-test",
    b"hostile",
    b"i219-init",
    b"install-consent=",
    b"kernel-fault-test",
    b"late-entry",
    b"machine-recover-test",
    b"masked-vector",
    b"mwm-demo",
    b"mwm-fault",
    b"native-install",
    b"net-i219",
    b"nic-ring-fault",
    b"nic-tx-hold",
    b"nic-tx-hold-stuck",
    b"nvme-qualify-verify",
    b"nvme-qualify-write",
    b"nvme-write=",
    b"pcm-death",
    b"pcm-enable",
    b"pcm-probe",
    b"pcm-stop",
    b"pcm-tone",
    b"pcm-underrun",
    b"reset-timeout",
    b"rt-class",
    b"rt-test",
    b"rtl8125-hold=",
    b"rtl8125-hole",
    b"rtl8125-linkdiag",
    b"rtl8125-loopback",
    b"rtl8125-no-loopback",
    b"rtl8125-phy",
    b"rtl8125-probe",
    b"rtl8125-short-rx",
    b"rtl8125-wire",
    b"rtl8125-wire-passes=",
    b"served-fsd-exit-test",
    b"served-fsd-hang-test",
    b"smp-ap-app",
    b"smp-ap-rt-refuse",
    b"smp-ap-user-refuse",
    b"smp-app-cpu=",
    b"smp-app-leaf-meter",
    b"smp-app-scale-bad-output",
    b"smp-app-scale-no-timer",
    b"smp-app-skip-timer",
    b"smp-bench-up",
    b"smp-bsp-app",
    b"smp-bsp-frame-budget-mutant",
    b"smp-bsp-refusal-mutant",
    b"smp-capacity-ignore-reservation",
    b"smp-cpus=",
    b"smp-cpus=2",
    b"smp-cpus=4",
    b"smp-cpus=6",
    b"smp-created-stop",
    b"smp-device-first-poll",
    b"smp-fpu-crosswire",
    b"smp-fpu-migration-test",
    b"smp-fpu-skip-restore",
    b"smp-kernel-only",
    b"smp-lifecycle",
    b"smp-migrate-early",
    b"smp-multicore-pressure",
    b"smp-nvme-skip-first-poll",
    b"smp-nway-restore-sentinel",
    b"smp-nway-retained-cancel",
    b"smp-nway-terminal-cpu",
    b"smp-nway-test",
    b"smp-queue-duplicate",
    b"smp-queue-lost",
    b"smp-real-app-scale",
    b"smp-rt-core-policy",
    b"smp-scale-meter-off",
    b"smp-scale-omit-path",
    b"smp-scale-short-work",
    b"smp-scale-test",
    b"smp-scale-wrong-path",
    b"smp-scheduler-test",
    b"smp-startup-fail-actor",
    b"smp-startup-last-window-omit",
    b"smp-startup-nway-test",
    b"smp-startup-skip-map",
    b"smp-timer-disabled",
    b"smp-timer-fpu-restore",
    b"smp-timer-no-eoi",
    b"smp-timer-no-schedule",
    b"smp-timer-return-reset",
    b"smp-timer-rt-owner",
    b"smp-user-bench",
    b"smp-user-double-claim",
    b"smp-user-early-ack",
    b"smp-user-early-finish",
    b"smp-user-lost-wake",
    b"smp-user-preempt",
    b"smp-user-pressure",
    b"smp-user-serialized",
    b"smp-user-startup",
    b"smp-user-test",
    b"survey",
    b"tsc-calibration-stall",
    b"usb-keyboard",
    b"usb-keyboard-fault=",
    b"usb-keyboard-observe",
    b"usb-keyboard-recover",
    b"usb-keyboard-recovery-test=",
    b"usb-keyboard-test",
    b"whole-ram-test",
    b"xhci-controller",
    b"xhci-fault=",
    b"xhci-firmware=",
    b"xhci-hotplug",
    b"xhci-observe",
    b"xhci-pagesize=",
    b"xhci-probe",
    b"xhci-rounds=",
    b"xhci-scratchpads=",
];

/// Words that start a named driver, so a census cannot carry them.
const DRIVER_WORDS: &[&[u8]] = &[b"ahci-disk=", b"ahci-write=", b"net-rtl8125"];

fn hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// `BB:DD.F`, lower-case hexadecimal, exactly that long.
fn address(text: &[u8]) -> Option<Bdf> {
    let &[b1, b0, b':', d1, d0, b'.', f] = text else {
        return None;
    };
    let device = hex(d1)? << 4 | hex(d0)?;
    let function = hex(f)?;
    if device > 0x1f || function > 7 {
        return None;
    }
    Some(Bdf {
        bus: hex(b1)? << 4 | hex(b0)?,
        device,
        function,
    })
}

/// The value of `dma-contain=`: `none`, or comma-separated `driver@BB:DD.F`
/// with at most one entry per driver.
pub fn parse(word: &[u8]) -> Result<Word, WordRefusal> {
    if word.is_empty() {
        return Err(WordRefusal::Empty);
    }
    let mut found = Word {
        ahci: None,
        rtl8125: None,
    };
    if word == b"none" {
        return Ok(found);
    }
    for entry in word.split(|&byte| byte == b',') {
        let at = entry
            .iter()
            .position(|&byte| byte == b'@')
            .ok_or(WordRefusal::UnknownDriver)?;
        let slot = match &entry[..at] {
            b"ahci" => &mut found.ahci,
            b"rtl8125" => &mut found.rtl8125,
            _ => return Err(WordRefusal::UnknownDriver),
        };
        if slot.is_some() {
            return Err(WordRefusal::DuplicateDriver);
        }
        *slot = Some(address(&entry[at + 1..]).ok_or(WordRefusal::Address)?);
    }
    if found.ahci.is_some() && found.ahci == found.rtl8125 {
        return Err(WordRefusal::SameFunction);
    }
    Ok(found)
}

/// Whether the rest of the boot line can run with `word`. `has(w)` answers
/// whether the line holds boot word `w` in any position; for a word ending in
/// `=`, one with that prefix. A conflict counts wherever it appears.
/// `selected(w)` answers whether `w` is where its consumer reads it: a word in
/// a position its consumer ignores has selected nothing.
pub fn check_options(
    word: &Word,
    has: impl Fn(&[u8]) -> bool,
    selected: impl Fn(&[u8]) -> bool,
) -> Result<(), WordRefusal> {
    if !cfg!(absd_mutant_contain_conflict_ignored) && REFUSED_WORDS.iter().any(|w| has(w)) {
        return Err(WordRefusal::Conflict);
    }
    if word.is_census() && DRIVER_WORDS.iter().any(|w| has(w)) {
        return Err(WordRefusal::Conflict);
    }
    if word.ahci.is_none() && has(b"dma-contain-check") {
        return Err(WordRefusal::CheckNeedsDisk);
    }
    if word.ahci.is_some() && !selected(b"ahci-disk=") && !selected(b"ahci-write=") {
        return Err(WordRefusal::NeedsDisk);
    }
    if word.rtl8125.is_some() {
        if !selected(b"net-rtl8125") {
            return Err(WordRefusal::NeedsNetBackend);
        }
        if !selected(b"net") && !selected(b"net-probe") {
            return Err(WordRefusal::NeedsNetProbe);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
