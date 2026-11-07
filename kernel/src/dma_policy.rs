//! The DMA containment seam's policy (#111 DESIGN §0, §5): what each
//! bus-mastering driver declares about the memory its device can reach,
//! and whether arming bus mastering is allowed under a profile. Pure; the
//! one place that sets PCI command bit 2 is `dma::arm` in the kernel
//! (src/dma.rs), which asks [`decide`].
//!
//! The enforcement point is the shared PCI layer, not driver goodwill.
//! In the kernel (src/pci.rs) the configuration ports are reached only
//! through a private module whose one writer takes a value that either
//! passed [`guard_command_write`] (which never sets Bus Master Enable) or
//! was built from a `dma::Armed` token that only `dma::arm` can construct.
//! For safe Rust that is a type-level guarantee. It does not cover
//! `unsafe` port I/O elsewhere naming the configuration ports; the source
//! check in this module's tests is a heuristic tripwire for that (it reads
//! literal port numbers and new port-output sites, not computed ones), and
//! `pci::write32` also counts any refused set at run time. The guard
//! function is host-tested here and mutated (`absd_mutant_pci_raw_bme`);
//! the writer around it runs only in the kernel.
//!
//! Increment 2's checkpoint is observational (owner decision 2026-10-30):
//! the boot runs in [`Profile::Recording`], which admits every declaration
//! exactly as before and only records and reports it. No existing driver is
//! labelled contained and there is no exempt state; the declarations below
//! are facts (`Assumed(VmTrusted)` or `Unavailable`, i.e. uncontained).
//! [`Profile::Enforced`] is selected only by increment 3's two AMD-Vi test
//! boots (`amdvi-enforce-test`, `amdvi-oracle=1`; src/amdvi_hw.rs), which
//! start no other bus-mastering driver and arm one function as
//! [`State::Contained`] after its domain is live; every other boot runs
//! `Recording`. How the existing physical paths should behave under
//! `Enforced` is an open owner decision (DECISIONS.md 2). Either answer is expressible here: a
//! physical path refused under `Enforced` keeps its declaration; one that
//! stays runnable does so under `Recording`, whose records name it
//! uncontained.
//!
//! A `dma-contain` boot (src/amdvi_hw/contain.rs) is also `Enforced`, and
//! every arm passes [`contain_gate`] first.
//!
//! Physical-support blocker (UNESTABLISHED, recorded 2026-10-31): the seam
//! mediates new Bus Master Enable sets only. Controlling future grants does
//! not establish control over DMA authority exercised before the kernel
//! arrived: functions firmware left bus-mastering are outside containment
//! in normal boots (`dma::report_inherited` lists them in every boot;
//! production boots never clear them). The AMD-Vi test boots block them by
//! DTE once their invalidation completes after IommuEn, and clear them (R2
//! only) when they refuse (#111 increment 6).

/// Why no containment is claimed but arming is acceptable by declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assumption {
    /// An emulated device in a VM the release trusts (QEMU guests, CI).
    VmTrusted,
}

/// Why a function cannot be contained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailability {
    /// No remapping backend implements containment for this path yet
    /// (AMD-Vi domains are increment 3; VT-d and SMMU are not scoped).
    NoBackend,
    /// No usable IVRS unit on this machine.
    NoUnit,
    /// The function's isolation group could not be verified.
    GroupUnverified,
}

/// A function's containment for the boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// An ABSD-programmed unit translates this function through a domain
    /// that maps only its grant. Nothing produces this in increment 2.
    Contained {
        unit: u8,
        domain: u16,
    },
    Assumed(Assumption),
    Unavailable(Unavailability),
}

impl State {
    pub fn name(&self) -> &'static str {
        match self {
            State::Contained { .. } => "contained",
            State::Assumed(Assumption::VmTrusted) => "assumed(vm-trusted)",
            State::Unavailable(Unavailability::NoBackend) => "unavailable(no-backend)",
            State::Unavailable(Unavailability::NoUnit) => "unavailable(no-unit)",
            State::Unavailable(Unavailability::GroupUnverified) => "unavailable(group-unverified)",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Increment 2's only boot profile: arm as before, record the state,
    /// claim nothing. Records name non-contained functions uncontained.
    Recording,
    /// Arm only `Contained` functions; no flag overrides it.
    Enforced,
}

impl Profile {
    pub fn name(&self) -> &'static str {
        match self {
            Profile::Recording => "recording",
            Profile::Enforced => "enforced",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Arm,
    Refuse,
}

pub fn decide(profile: Profile, state: State) -> Decision {
    match (profile, state) {
        (Profile::Recording, _) | (Profile::Enforced, State::Contained { .. }) => Decision::Arm,
        _ if cfg!(absd_mutant_dma_enforced_arms) => Decision::Arm,
        (Profile::Enforced, _) => Decision::Refuse,
    }
}

/// What a declaration needs from its caller before `dma::arm` may arm it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Witness {
    /// Nothing beyond the declaration.
    None,
    /// A [`VmEnvelopeObserved`] token: ABSD's VM-environment check passed
    /// (detected, not verified).
    VmEnvelopeObserved,
    /// Only in a `dma-contain` boot, which is always `Enforced`: `Recording`
    /// must not arm a declaration whose only trust is a live domain.
    ContainMode,
}

/// Token that ABSD's VM-environment check passed: CPUID hypervisor bit
/// set, the KVM signature, the q35 host bridge (`rtl8125_pci::containment`,
/// which reads CPUID itself through `rtl8125_pci::Envelope::probe`). Named
/// for what it proves: the envelope was *observed*. It does not
/// authenticate the hypervisor. Those three are compatibility signals, not
/// an enforceable security boundary; a hostile or emulated platform can
/// present all three. Its only constructor is crate-private, so safe Rust
/// outside this library (every driver in the kernel binary, using the
/// library API) cannot make one without running that check (privacy does
/// not stop `unsafe` code fabricating this zero-sized value): a driver that skips it does not compile against
/// `dma::arm_in_vm`, and `dma::arm` refuses a declaration that needs one.
/// The token makes the admission path structural and nothing more.
#[derive(Debug, Eq, PartialEq)]
pub struct VmEnvelopeObserved {
    _checked: (),
}

impl VmEnvelopeObserved {
    pub(crate) fn checked() -> VmEnvelopeObserved {
        VmEnvelopeObserved { _checked: () }
    }
}

/// Why `dma::arm` refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The profile refuses this state (an enforced boot, anything but
    /// `Contained`).
    Profile,
    /// The declaration needs a witness the caller did not present (an
    /// `Assumed(VmTrusted)` path outside, or without, its VM envelope check).
    WitnessMissing,
    /// Contain mode: no current registration for this function and owner.
    NotRegistered,
    /// Contain mode: the unit failed; nothing arms for the rest of the boot.
    Latched,
}

impl Refusal {
    pub fn word(self) -> &'static str {
        match self {
            Refusal::Profile => "profile",
            Refusal::WitnessMissing => "witness-missing",
            Refusal::NotRegistered => "not-registered",
            Refusal::Latched => "latched",
        }
    }
}

/// The arm decision for a declaration and the witness the caller holds.
pub fn admit(
    profile: Profile,
    declaration: &Declaration,
    witness: Option<&VmEnvelopeObserved>,
) -> Result<(), Refusal> {
    if declaration.witness == Witness::VmEnvelopeObserved
        && witness.is_none()
        && !cfg!(absd_mutant_dma_witness_ignored)
    {
        return Err(Refusal::WitnessMissing);
    }
    if declaration.witness == Witness::ContainMode && profile != Profile::Enforced {
        return Err(Refusal::WitnessMissing);
    }
    match decide(profile, declaration.state) {
        Decision::Arm => Ok(()),
        Decision::Refuse => Err(Refusal::Profile),
    }
}

/// The state `dma::arm` decides on: the declaration's, unless an
/// ABSD-programmed domain is live for the function in this boot
/// (`contained` = its DomainID), which makes it `Contained` on unit 0
/// (#116). A declaration is a compile-time fact; containment is a run-time
/// one, so the seam needs both (abstraction leak L4). `Assumed` paths are
/// never upgraded: they arm under their own witness rule.
pub fn effective_state(declared: State, contained: Option<u16>) -> State {
    match (declared, contained) {
        (State::Unavailable(_), Some(domain)) if !cfg!(absd_mutant_dma_registry_ignored) => {
            State::Contained { unit: 0, domain }
        }
        (declared, _) => declared,
    }
}

/// The functions an ABSD-programmed domain contains right now, with their
/// DomainIDs (#116, the dma seam's live-domain record): at most `N`; a
/// function appears at most once; registering again replaces its entry.
#[derive(Clone, Copy, Debug)]
pub struct LiveDomains<F: Copy + PartialEq, const N: usize> {
    slots: [Option<(F, u16)>; N],
}

impl<F: Copy + PartialEq, const N: usize> LiveDomains<F, N> {
    pub const EMPTY: Self = LiveDomains { slots: [None; N] };

    /// Records `domain` for `function`, replacing any earlier entry.
    /// Returns false (and records nothing) when the record is full.
    pub fn register(&mut self, function: F, domain: u16) -> bool {
        self.release(function);
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some((function, domain));
                true
            }
            None => false,
        }
    }

    /// The function's domain is no longer live.
    pub fn release(&mut self, function: F) {
        if cfg!(absd_mutant_dma_release_ignored) {
            return;
        }
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|(f, _)| f == function) {
                *slot = None;
            }
        }
    }

    pub fn domain(&self, function: F) -> Option<u16> {
        self.slots
            .iter()
            .flatten()
            .find(|(f, _)| *f == function)
            .map(|&(_, domain)| domain)
    }
}

/// Every arm in a `dma-contain` boot passes this first, whatever declared
/// state or retained proof the caller holds. `registered` is the function's
/// current [`ContainRegistry`] domain for this owner; `latched` is the
/// terminal unit-failure latch. Outside contain mode it decides nothing.
pub fn contain_gate(
    contain_mode: bool,
    registered: Option<u16>,
    latched: bool,
) -> Result<(), Refusal> {
    if !contain_mode || cfg!(absd_mutant_contain_gate_open) {
        return Ok(());
    }
    if latched && !cfg!(absd_mutant_contain_latch_ignored) {
        return Err(Refusal::Latched);
    }
    match registered {
        Some(_) => Ok(()),
        None => Err(Refusal::NotRegistered),
    }
}

/// The contain-mode record of live domains, each bound to the owner it was
/// granted for. A function is registered at most once per boot: its surface
/// is never re-granted, so neither a released target nor a stale proof can
/// come back. The test boots keep [`LiveDomains`] and their restart path.
#[derive(Clone, Copy, Debug)]
pub struct ContainRegistry<F: Copy + PartialEq, const N: usize> {
    slots: [Option<(F, &'static str, u16, bool)>; N],
}

impl<F: Copy + PartialEq, const N: usize> ContainRegistry<F, N> {
    pub const EMPTY: Self = ContainRegistry { slots: [None; N] };

    /// False, recording nothing, when the function was ever registered or
    /// the record is full.
    pub fn register(&mut self, function: F, owner: &'static str, domain: u16) -> bool {
        if !cfg!(absd_mutant_contain_reregister)
            && self.slots.iter().flatten().any(|s| s.0 == function)
        {
            return false;
        }
        if cfg!(absd_mutant_contain_reregister) {
            for slot in self.slots.iter_mut() {
                if slot.is_some_and(|s| s.0 == function) {
                    *slot = None;
                }
            }
        }
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some((function, owner, domain, true));
                true
            }
            None => false,
        }
    }

    pub fn release(&mut self, function: F) {
        for slot in self.slots.iter_mut().flatten() {
            if slot.0 == function {
                slot.3 = false;
            }
        }
    }

    pub fn release_all(&mut self) {
        for slot in self.slots.iter_mut().flatten() {
            slot.3 = false;
        }
    }

    /// The live domain of this function for this owner.
    pub fn domain(&self, function: F, owner: &str) -> Option<u16> {
        self.slots
            .iter()
            .flatten()
            .find(|s| {
                s.0 == function && s.3 && (s.1 == owner || cfg!(absd_mutant_contain_owner_ignored))
            })
            .map(|s| s.2)
    }
}

/// What a driver says about its bus-master path, once, in this table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Declaration {
    /// The owner name the driver claims the function with (`pci::claim`).
    pub owner: &'static str,
    pub state: State,
    /// Where the path runs, for the record (a label: it confines nothing).
    pub environments: &'static str,
    /// What the caller must present before arming.
    pub witness: Witness,
}

// `environments` is a label and confines nothing. Of the `Assumed(VmTrusted)`
// declarations only RTL8125 is structurally confined (a
// `VmEnvelopeObserved` token). Without a seam-level requirement, `e1000`
// (8086:100e) and `virtio-sound` (1af4:1059) would arm on bare metal if the
// matching function were present; `ata-bmide` (8086:7010) is refused on
// bare metal by its own driver (`ata::dma_probe` requires the CPUID
// hypervisor bit and QEMU's disk model before PCI discovery), not by the
// seam. Unchanged; owner decision, DESIGN §5.
// Each caller's declared state at 6564ece (PREFLIGHT §5.2). The QEMU-only
// paths are `Assumed(VmTrusted)`: the kernel does not detect the VM, the
// declaration says the path is only exercised there. Every path that also
// runs on a physical machine is `Unavailable(NoBackend)` until a backend
// contains it.
pub const E1000: Declaration = Declaration {
    owner: "e1000",
    state: State::Assumed(Assumption::VmTrusted),
    environments: "qemu",
    witness: Witness::None,
};
pub const VIRTIO_SOUND: Declaration = Declaration {
    owner: "virtio-sound",
    state: State::Assumed(Assumption::VmTrusted),
    environments: "qemu",
    witness: Witness::None,
};
pub const ATA_BMIDE: Declaration = Declaration {
    owner: "ata-bmide",
    state: State::Assumed(Assumption::VmTrusted),
    environments: "qemu",
    witness: Witness::None,
};
pub const NVME: Declaration = Declaration {
    owner: "nvme",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "qemu physical",
    witness: Witness::None,
};
pub const XHCI: Declaration = Declaration {
    owner: "xhci",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "qemu z2 e5",
    witness: Witness::None,
};
pub const AHCI: Declaration = Declaration {
    owner: "ahci-census",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "qemu z2 e5",
    witness: Witness::None,
};
/// The AHCI block backend (src/ahci_block.rs): one declared SATA disk. Its
/// physical target is hardware_fixture's FCH SATA controller (#123), where AMD-Vi
/// containment is the next slice; until then it is uncontained.
pub const AHCI_BLOCK: Declaration = Declaration {
    owner: "ahci",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "qemu hardware_fixture",
    witness: Witness::None,
};
pub const I219: Declaration = Declaration {
    owner: "i219-spt",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "z2",
    witness: Witness::None,
};

/// RTL8125B (#109). DMA trust in a VM rests on a declared operating
/// assumption: an honest KVM host whose IOMMU contains the passthrough
/// device. ABSD detects that environment but does not verify it, and the
/// host's IOMMU is not ABSD enforcement. Admission is structural: the
/// declaration needs a [`VmEnvelopeObserved`] token, which only a passed
/// VM-environment check constructs, so `dma::arm` refuses it without one
/// (`WitnessMissing`). On bare metal RTL8125 is Unavailable until ABSD's own
/// AMD-Vi contains it (DESIGN §5); no bare-metal arm exists.
pub const RTL8125: Declaration = Declaration {
    owner: "rtl8125",
    state: State::Assumed(Assumption::VmTrusted),
    environments: "qemu",
    witness: Witness::VmEnvelopeObserved,
};

/// RTL8125 in a `dma-contain` boot (design section 7): trusted only through
/// a live domain, so it arms nowhere else. Not in [`DECLARATIONS`], which
/// holds one declaration per owner: this is the same owner's other path.
pub const RTL8125_CONTAINED: Declaration = Declaration {
    owner: "rtl8125",
    state: State::Unavailable(Unavailability::NoBackend),
    environments: "hardware_fixture reference_host-vfio",
    witness: Witness::ContainMode,
};

pub const DECLARATIONS: [&Declaration; 9] = [
    &E1000,
    &VIRTIO_SOUND,
    &ATA_BMIDE,
    &NVME,
    &XHCI,
    &AHCI,
    &AHCI_BLOCK,
    &I219,
    &RTL8125,
];

/// A bounded record of distinct items (the inherited bus masters, #111
/// increment 6): an item already present is not added again; an item that
/// does not fit sets `overflow`, which the caller must not ignore (the
/// AMD-Vi boots refuse to enable on an incomplete record).
#[derive(Clone, Copy, Debug)]
pub struct BoundedSet<T: Copy + PartialEq, const N: usize> {
    items: [Option<T>; N],
    overflow: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    Added,
    Present,
    Overflow,
}

impl<T: Copy + PartialEq, const N: usize> BoundedSet<T, N> {
    pub const EMPTY: Self = BoundedSet {
        items: [None; N],
        overflow: false,
    };

    /// Adds `item` unless an item with the same `key` is present.
    pub fn insert_by<K: PartialEq>(&mut self, item: T, key: impl Fn(&T) -> K) -> Insert {
        let k = key(&item);
        if self.items.iter().flatten().any(|i| key(i) == k) {
            return Insert::Present;
        }
        match self.items.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(item);
                Insert::Added
            }
            None => {
                if !cfg!(absd_mutant_dma_inherited_overflow_ignored) {
                    self.overflow = true;
                }
                Insert::Overflow
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.items.iter().flatten().copied()
    }

    pub fn overflow(&self) -> bool {
        self.overflow
    }
}

/// PCI command register bit 2, Bus Master Enable.
pub const BUS_MASTER: u32 = 1 << 2;

/// The shared PCI layer's guard on every configuration write that is not
/// `dma::arm`'s: a write to the command dword (offset 04h) may keep or
/// clear Bus Master Enable but never set it. `current` is the command
/// register as read before the write. Returns the value to write and
/// whether a set was refused.
pub fn guard_command_write(current: u16, requested: u32) -> (u32, bool) {
    let setting = requested & BUS_MASTER != 0 && u32::from(current) & BUS_MASTER == 0;
    if setting && !cfg!(absd_mutant_pci_raw_bme) {
        (requested & !BUS_MASTER, true)
    } else {
        (requested, false)
    }
}

#[cfg(test)]
mod tests;
