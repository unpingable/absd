extern crate std;
use super::*;
use std::format;
use std::fs;
use std::path::Path;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

const STATES: [State; 5] = [
    State::Contained { unit: 0, domain: 1 },
    State::Assumed(Assumption::VmTrusted),
    State::Unavailable(Unavailability::NoBackend),
    State::Unavailable(Unavailability::NoUnit),
    State::Unavailable(Unavailability::GroupUnverified),
];

#[test]
fn recording_arms_every_state() {
    for state in STATES {
        assert_eq!(
            decide(Profile::Recording, state),
            Decision::Arm,
            "{state:?}"
        );
    }
}

#[test]
fn enforced_refuses_everything_but_contained() {
    for state in STATES {
        let expected = if matches!(state, State::Contained { .. }) {
            Decision::Arm
        } else {
            Decision::Refuse
        };
        assert_eq!(decide(Profile::Enforced, state), expected, "{state:?}");
    }
}

#[test]
fn declarations_are_distinct_and_never_contained() {
    for (index, declaration) in DECLARATIONS.iter().enumerate() {
        assert!(!matches!(declaration.state, State::Contained { .. }));
        assert!(
            DECLARATIONS[..index]
                .iter()
                .all(|other| other.owner != declaration.owner)
        );
    }
    // The physical paths are the ones an enforced boot would refuse.
    let refused: Vec<&str> = DECLARATIONS
        .iter()
        .filter(|d| decide(Profile::Enforced, d.state) == Decision::Refuse)
        .map(|d| d.owner)
        .collect();
    assert_eq!(refused.len(), DECLARATIONS.len());
    let physical: Vec<&str> = DECLARATIONS
        .iter()
        .filter(|d| d.environments.split(' ').any(|e| e != "qemu"))
        .map(|d| d.owner)
        .collect();
    assert_eq!(
        physical,
        ["nvme", "xhci", "ahci-census", "ahci", "i219-spt"]
    );
    for owner in &physical {
        let declaration = DECLARATIONS.iter().find(|d| d.owner == *owner).unwrap();
        assert_eq!(
            declaration.state,
            State::Unavailable(Unavailability::NoBackend)
        );
    }
}

/// Files that may name the PCI configuration ports or command bit 2.
const PCI: &str = "src/pci.rs";
const DMA: &str = "src/dma.rs";
/// Files with port-output code today (fixed ports: serial, debug exit,
/// ATA, ACPI PM1, the 0xcf9 reset, PCI). A new one must be added here by
/// hand, so it is seen in review.
const PORT_OUTPUT_FILES: &[&str] = &[
    "src/acpi_boot.rs",
    "src/ap.rs",
    "src/arch/x86_64/syscall_platform.rs",
    "src/ata.rs",
    "src/cpu.rs",
    "src/main.rs",
    "src/pci.rs",
    "src/serial.rs",
];

/// Integer literals in a line of code, in every radix Rust accepts (hex,
/// octal, binary, decimal; case, `_`, zero padding, type suffix). Float,
/// char and byte-string spellings, and macro- or const-computed values, are
/// not read.
fn literals(code: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let starts = bytes[at].is_ascii_digit()
            && (at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_'));
        if !starts {
            at += 1;
            continue;
        }
        let mut end = at;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let token: String = code[at..end].chars().filter(|&c| c != '_').collect();
        let lower = token.to_ascii_lowercase();
        let radix = |rest: &str, radix: u32| {
            let digits: String = rest.chars().take_while(|c| c.is_digit(radix)).collect();
            u64::from_str_radix(&digits, radix).ok()
        };
        let value = if let Some(hex) = lower.strip_prefix("0x") {
            radix(hex, 16)
        } else if let Some(octal) = lower.strip_prefix("0o") {
            radix(octal, 8)
        } else if let Some(binary) = lower.strip_prefix("0b") {
            radix(binary, 2)
        } else {
            let digits: String = lower.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        };
        out.extend(value);
        at = end;
    }
    out
}

/// Configuration mechanism #1: the dword address port and the data ports.
fn config_port(value: u64) -> bool {
    value == 0xcf8 || (0xcfc..=0xcff).contains(&value)
}

/// The line range of `mod port { ... }` in pci.rs.
fn port_module(lines: &[&str]) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| l.starts_with("mod port {"))?;
    let end = start + lines[start..].iter().position(|l| *l == "}")?;
    Some((start, end))
}

/// A tripwire, not a proof (src/pci.rs module documentation): the type
/// structure is what keeps safe code from setting Bus Master Enable; this
/// catches the ways around it that types cannot see when they are spelled
/// plainly. A computed port number, or new code in a file already on
/// `PORT_OUTPUT_FILES`, still evades it.
fn violations(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        let port = if path == PCI {
            port_module(&lines)
        } else {
            None
        };
        if path == PCI && port.is_none() {
            found.push(format!("{path}: no `mod port` block"));
        }
        let in_port =
            |number: usize| port.is_some_and(|(start, end)| start <= number && number <= end);
        for (number, line) in lines.iter().enumerate() {
            let at = format!("{path}:{}", number + 1);
            let code = line.split("//").next().unwrap_or("");
            if literals(code).into_iter().any(config_port) && !in_port(number) {
                found.push(format!(
                    "{at}: PCI configuration port outside pci.rs `mod port`"
                ));
            }
            if path != PCI && code.contains("COMMAND_BUS_MASTER") {
                found.push(format!("{at}: PCI command bit constant outside pci.rs"));
            }
            let output = ["\"out ", "outb(", "outw(", "outl("]
                .iter()
                .any(|needle| code.contains(needle));
            if output && !PORT_OUTPUT_FILES.contains(&path.as_str()) {
                found.push(format!("{at}: port output in a file not on the list"));
            }
            if path == PCI && output && !in_port(number) {
                found.push(format!("{at}: port output in pci.rs outside `mod port`"));
            }
            if code.contains("Checked {") && !in_port(number) {
                found.push(format!("{at}: port::Checked built outside `mod port`"));
            }
            if code.contains("Armed {") && !code.contains("struct Armed {") && path != DMA {
                found.push(format!("{at}: Armed constructed outside dma.rs"));
            }
            for setter in ["set_polled_dma(", "set_ide_dma("] {
                if code.contains(setter)
                    && path != DMA
                    && !(path == PCI && code.contains("pub fn "))
                {
                    found.push(format!("{at}: {setter} outside dma.rs"));
                }
            }
        }
    }
    found
}

fn tree() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                // The lint and its negative controls quote what they forbid.
                && !path.ends_with("dma_policy/tests.rs")
            {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.push((name, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(&root.join("src"), root, &mut out);
    assert!(out.len() > 50, "source tree not found");
    out
}

#[test]
fn only_dma_arm_sets_bus_mastering() {
    let files = tree();
    assert_eq!(violations(&files), Vec::<String>::new());
    // The structure the guarantee rests on: the setters take the token
    // (no separate function argument), the token's field is private and it
    // is neither Clone nor Copy, and `write32` goes through the guard.
    let text = |name: &str| &files.iter().find(|(path, _)| path == name).unwrap().1;
    assert!(text(PCI).contains("pub fn set_polled_dma(armed: crate::dma::Armed)"));
    assert!(text(PCI).contains("pub fn set_ide_dma(armed: crate::dma::Armed)"));
    let dma = text(DMA);
    let armed = dma
        .find("pub struct Armed {\n    function: Function,\n}")
        .expect("Armed");
    assert!(
        !dma[..armed].trim_end().ends_with(")]"),
        "Armed derives nothing"
    );
    let pci = text(PCI);
    let body = &pci[pci.find("pub fn write32(").unwrap()..];
    let body = &body[..body.find("\n}\n").unwrap()];
    assert!(body.contains("port::guarded("), "write32 must guard");
    let lines: Vec<&str> = pci.lines().collect();
    let (start, end) = port_module(&lines).unwrap();
    let module = lines[start..=end].join("\n");
    assert!(module.contains("    pub struct Checked {\n        function: Function,"));
    assert!(module.contains("guard_command_write("));
    assert_eq!(
        module.matches("pub fn ").count(),
        4,
        "guarded, armed, read, write"
    );
}

#[test]
fn every_former_enable_routes_through_arm_with_its_declaration() {
    let files = tree();
    let text = |name: &str| &files.iter().find(|(path, _)| path == name).unwrap().1;
    for (file, constant, owner) in [
        ("src/e1000.rs", "E1000", "e1000"),
        ("src/virtio_sound.rs", "VIRTIO_SOUND", "virtio-sound"),
        ("src/ata.rs", "ATA_BMIDE", "ata-bmide"),
        ("src/nvme.rs", "NVME", "nvme"),
        ("src/xhci.rs", "XHCI", "xhci"),
        ("src/ahci.rs", "AHCI", "ahci-census"),
        ("src/ahci_block.rs", "AHCI_BLOCK", "ahci"),
        ("src/i219_device.rs", "I219", "i219-spt"),
        ("src/rtl8125_device.rs", "RTL8125", "rtl8125"),
    ] {
        let source = text(file);
        assert!(
            source.contains(&format!("dma_policy::{constant})"))
                || source.contains(&format!("dma_policy::{constant}, &observed)")),
            "{file} arms with {constant}"
        );
        assert!(
            source.contains(&format!("\"{owner}\"")),
            "{file} claims as {owner}"
        );
        assert!(
            !source.contains("enable_polled_dma") && !source.contains("enable_ide_dma"),
            "{file}"
        );
        // No driver-local Bus Master Enable set survives (#109 merged with
        // #111: RTL8125 once set it through its own command write).
        assert!(
            !source.contains("| BUS_MASTER)"),
            "{file} sets bus mastering itself"
        );
    }
    let arms: usize = files
        .iter()
        .map(|(_, text)| {
            text.matches("dma::arm(").count()
                + text.matches("dma::arm_ide(").count()
                + text.matches("dma::arm_in_vm(").count()
        })
        .sum();
    // One per declared driver, RTL8125's contained path, and the fixture's
    // re-arm probe (which the gate must refuse).
    assert_eq!(arms, 11, "one arm per declared driver");
}

fn file(path: &str, text: &str) -> (String, String) {
    (path.to_string(), text.to_string())
}

#[test]
fn the_lint_catches_each_plain_bypass() {
    let pci_ok = file(
        PCI,
        "mod port {\n    const DATA: u16 = 0xcfc;\n    pub struct Checked {\n    }\n    pub fn armed(armed: Armed, c: u16) -> Checked { Checked { function } }\n    unsafe fn outl(port: u16, value: u32) {}\n}\npub fn set_polled_dma(armed: crate::dma::Armed) {\n    let c = v | COMMAND_BUS_MASTER;\n}\n",
    );
    let dma_ok = file(
        DMA,
        "pub struct Armed {\n    function: Function,\n}\nfn arm() { pci::set_polled_dma(Armed { function }); }\n",
    );
    let reset = file(
        "src/main.rs",
        "    asm!(\"out dx, al\", in(\"dx\") 0xcf9u16);\n",
    );
    assert!(violations(&[pci_ok.clone(), dma_ok.clone(), reset]).is_empty());
    let cases = [
        // The configuration ports outside `mod port`, in any integer radix.
        file("src/serial.rs", "    outb(0xcfc, value);\n"),
        file("src/serial.rs", "    outb(0xCFD, value);\n"),
        file("src/serial.rs", "    let p = 0x0cfe_u16;\n"),
        file("src/serial.rs", "    let p = 0xc_f8;\n"),
        file("src/serial.rs", "    let p: u16 = 3327;\n"),
        file("src/serial.rs", "    outb(0o6374, value);\n"),
        file("src/serial.rs", "    outb(0b1100_1111_1100, value);\n"),
        file("src/serial.rs", "    outb(0O6377u16, value);\n"),
        file(PCI, "mod port {\n}\nconst DATA: u16 = 0xcfc;\n"),
        // pci.rs without the module, or writing ports outside it.
        file(PCI, "unsafe fn outl(port: u16, value: u32) {}\n"),
        file(
            PCI,
            "mod port {\n}\nfn rogue() { unsafe { outl(DATA, v) } }\n",
        ),
        // Port output in a file not on the list.
        file(
            "src/rogue.rs",
            "    asm!(\"out dx, eax\", in(\"dx\") p, in(\"eax\") v);\n",
        ),
        file(
            "src/rogue.rs",
            "    unsafe { crate::serial::outb(p, v) };\n",
        ),
        // The command bit constant, the token or a Checked elsewhere.
        file("src/rogue.rs", "const COMMAND_BUS_MASTER: u16 = 4;\n"),
        file("src/rogue.rs", "    let t = Armed { function };\n"),
        file(
            PCI,
            "mod port {\n}\nfn f() -> Checked { Checked { function, offset, value } }\n",
        ),
        // The setter outside dma.rs.
        file("src/rogue.rs", "    pci::set_polled_dma(token);\n"),
    ];
    for case in cases {
        let files = if case.0 == PCI {
            vec![case.clone(), dma_ok.clone()]
        } else {
            vec![pci_ok.clone(), dma_ok.clone(), case.clone()]
        };
        assert!(!violations(&files).is_empty(), "missed: {}", case.1);
    }
    // What it does not catch: a computed port number in a listed file.
    let computed = file("src/serial.rs", "    outb(0xcf0 + 0xc, value);\n");
    assert!(violations(&[pci_ok, dma_ok, computed]).is_empty());
}

#[test]
fn raw_command_writes_cannot_set_bus_master() {
    // From BME clear: a write asking for it is written without it.
    assert_eq!(guard_command_write(0x0002, 0x0006), (0x0002, true));
    assert_eq!(
        guard_command_write(0x0000, 0x0000_0407),
        (0x0000_0403, true)
    );
    // Keeping it (restores, decode toggles) and clearing it are allowed.
    assert_eq!(guard_command_write(0x0006, 0x0006), (0x0006, false));
    assert_eq!(guard_command_write(0x0006, 0x0004), (0x0004, false));
    assert_eq!(guard_command_write(0x0006, 0x0002), (0x0002, false));
    assert_eq!(guard_command_write(0x0002, 0x0003), (0x0003, false));
    // The status half (zeros, so RW1C bits are not cleared) passes through.
    assert_eq!(
        guard_command_write(0x0000, 0xffff_0004),
        (0xffff_0000, true)
    );
}

#[test]
fn rtl8125_arms_only_with_the_vm_envelope_token() {
    use crate::rtl8125_pci::{self, Envelope, Uncontained};
    // Without the token RTL8125 is refused, by name, in every profile.
    for profile in [Profile::Recording, Profile::Enforced] {
        assert_eq!(admit(profile, &RTL8125, None), Err(Refusal::WitnessMissing));
    }
    // A bare-metal-shaped probe: no hypervisor bit, so no token, so refused.
    let bare = Envelope::for_test(false, [0; 12], 0x1630_1022);
    assert_eq!(
        rtl8125_pci::containment(&bare),
        Err(Uncontained::NoHypervisor)
    );
    let token = rtl8125_pci::containment(&bare).ok();
    assert_eq!(
        admit(Profile::Recording, &RTL8125, token.as_ref()),
        Err(Refusal::WitnessMissing)
    );
    assert_eq!(Refusal::WitnessMissing.word(), "witness-missing");
    // Inside the observed envelope the declaration decides as before.
    let vm = Envelope::for_test(
        true,
        rtl8125_pci::KVM_SIGNATURE,
        rtl8125_pci::Q35_HOST_BRIDGE,
    );
    let token = rtl8125_pci::containment(&vm).unwrap();
    assert_eq!(admit(Profile::Recording, &RTL8125, Some(&token)), Ok(()));
    assert_eq!(
        admit(Profile::Enforced, &RTL8125, Some(&token)),
        Err(Refusal::Profile)
    );
    // Only RTL8125 needs the token; the other declarations are unchanged.
    for declaration in DECLARATIONS {
        let needs = declaration.witness == Witness::VmEnvelopeObserved;
        assert_eq!(
            needs,
            declaration.owner == "rtl8125",
            "{}",
            declaration.owner
        );
        if !needs {
            assert_eq!(
                admit(Profile::Recording, declaration, None),
                Ok(()),
                "{}",
                declaration.owner
            );
        }
    }
}

#[test]
fn only_dma_arm_in_vm_takes_the_token() {
    // The token's constructor is crate-private and the driver arms through
    // `arm_in_vm` with the token from `containment`.
    let files = tree();
    let text = |name: &str| &files.iter().find(|(path, _)| path == name).unwrap().1;
    assert!(
        text("src/dma_policy.rs").contains("    pub(crate) fn checked() -> VmEnvelopeObserved {")
    );
    let device = text("src/rtl8125_device.rs");
    assert!(device.contains("dma::arm_in_vm(self.function, &dma_policy::RTL8125, &observed)"));
    for (path, source) in &files {
        if path != "src/dma_policy.rs" && path != "src/rtl8125_pci.rs" {
            assert!(!source.contains("VmEnvelopeObserved::checked()"), "{path}");
            assert!(!source.contains("VmEnvelopeObserved {"), "{path}");
        }
    }
}

#[test]
fn the_inherited_record_is_a_union_and_overflow_is_kept() {
    let mut set: BoundedSet<(u16, u16), 3> = BoundedSet::EMPTY;
    let key = |i: &(u16, u16)| i.0;
    // First snapshot.
    assert_eq!(set.insert_by((0x30, 0x0107), key), Insert::Added);
    assert_eq!(set.insert_by((0xfa, 0x0107), key), Insert::Added);
    // Second snapshot: the same function again (even with another command
    // value) is present; one that cleared its BME meanwhile stays recorded.
    assert_eq!(set.insert_by((0x30, 0x0106), key), Insert::Present);
    assert_eq!(set.insert_by((0x08, 0x0107), key), Insert::Added);
    let ids: std::vec::Vec<u16> = set.iter().map(|i| i.0).collect();
    assert_eq!(ids, [0x30, 0xfa, 0x08]);
    assert!(!set.overflow());
    // Full: a fourth distinct function overflows, and it stays overflowed.
    assert_eq!(set.insert_by((0x40, 0x0107), key), Insert::Overflow);
    assert!(set.overflow());
    assert_eq!(set.insert_by((0x30, 0x0107), key), Insert::Present);
    assert!(set.overflow());
}

#[test]
fn a_live_domain_makes_an_unavailable_declaration_contained() {
    // #116: NVMe declares Unavailable(NoBackend); a live domain for the
    // function in this boot makes it Contained and enforced arms it.
    let state = effective_state(NVME.state, Some(2));
    assert_eq!(state, State::Contained { unit: 0, domain: 2 });
    assert_eq!(decide(Profile::Enforced, state), Decision::Arm);
    // No domain: the declaration stands, and enforced refuses it.
    assert_eq!(effective_state(NVME.state, None), NVME.state);
    assert_eq!(
        decide(Profile::Enforced, effective_state(NVME.state, None)),
        Decision::Refuse
    );
    // An Assumed declaration is never upgraded by a domain.
    assert_eq!(effective_state(E1000.state, Some(2)), E1000.state);
    assert_eq!(effective_state(RTL8125.state, Some(2)), RTL8125.state);
}

#[test]
fn the_live_domain_record_registers_replaces_and_releases() {
    let mut live: LiveDomains<u16, 2> = LiveDomains::EMPTY;
    assert_eq!(live.domain(0x28), None);
    assert!(live.register(0x28, 1));
    assert!(live.register(0x38, 2));
    assert_eq!((live.domain(0x28), live.domain(0x38)), (Some(1), Some(2)));
    // Full: a third function is refused and nothing changes.
    assert!(!live.register(0x40, 3));
    assert_eq!(live.domain(0x40), None);
    // Registering again replaces, never duplicates.
    assert!(live.register(0x38, 2));
    live.release(0x38);
    assert_eq!(
        live.domain(0x38),
        None,
        "a released function is not contained"
    );
    assert_eq!(live.domain(0x28), Some(1), "releasing one leaves the other");
    assert!(live.register(0x40, 3));
    // What arm decides on: released means the declaration stands again.
    assert_eq!(effective_state(NVME.state, live.domain(0x38)), NVME.state);
}

#[test]
fn the_contain_gate_needs_a_registration_and_a_clear_latch() {
    assert_eq!(contain_gate(true, Some(2), false), Ok(()));
    assert_eq!(contain_gate(true, None, false), Err(Refusal::NotRegistered));
    assert_eq!(contain_gate(true, Some(2), true), Err(Refusal::Latched));
    assert_eq!(contain_gate(true, None, true), Err(Refusal::Latched));
}

#[test]
fn the_contain_gate_is_silent_outside_contain_mode() {
    for registered in [None, Some(2)] {
        for latched in [false, true] {
            assert_eq!(contain_gate(false, registered, latched), Ok(()));
        }
    }
}

#[test]
fn a_declared_contained_state_does_not_pass_the_gate_alone() {
    // `decide` alone would arm this; the gate is what refuses it.
    let declared = State::Contained { unit: 0, domain: 7 };
    assert_eq!(decide(Profile::Enforced, declared), Decision::Arm);
    assert_eq!(contain_gate(true, None, false), Err(Refusal::NotRegistered));
}

#[test]
fn a_contain_registration_is_bound_to_its_owner() {
    let mut registry: ContainRegistry<u16, 3> = ContainRegistry::EMPTY;
    assert!(registry.register(0x501, "ahci", 2));
    assert_eq!(registry.domain(0x501, "ahci"), Some(2));
    assert_eq!(registry.domain(0x501, "ahci-census"), None);
    assert_eq!(registry.domain(0x100, "ahci"), None);
    // So the census's declaration on the same function is not upgraded.
    assert_eq!(
        effective_state(AHCI.state, registry.domain(0x501, AHCI.owner)),
        AHCI.state
    );
    assert_eq!(
        effective_state(AHCI_BLOCK.state, registry.domain(0x501, AHCI_BLOCK.owner)),
        State::Contained { unit: 0, domain: 2 }
    );
}

#[test]
fn a_released_target_cannot_be_registered_again() {
    let mut registry: ContainRegistry<u16, 3> = ContainRegistry::EMPTY;
    assert!(registry.register(0x501, "ahci", 2));
    registry.release(0x501);
    assert_eq!(registry.domain(0x501, "ahci"), None);
    assert!(!registry.register(0x501, "ahci", 2));
    assert_eq!(registry.domain(0x501, "ahci"), None);
}

#[test]
fn a_second_registration_of_a_live_target_is_refused() {
    let mut registry: ContainRegistry<u16, 3> = ContainRegistry::EMPTY;
    assert!(registry.register(0x501, "ahci", 2));
    assert!(!registry.register(0x501, "ahci", 3));
    assert_eq!(registry.domain(0x501, "ahci"), Some(2));
}

#[test]
fn the_contain_registry_refuses_when_full() {
    let mut registry: ContainRegistry<u16, 1> = ContainRegistry::EMPTY;
    assert!(registry.register(0x501, "ahci", 2));
    assert!(!registry.register(0x100, "rtl8125", 3));
}

#[test]
fn release_all_empties_the_registry_and_keeps_it_closed() {
    let mut registry: ContainRegistry<u16, 3> = ContainRegistry::EMPTY;
    assert!(registry.register(0x501, "ahci", 2));
    assert!(registry.register(0x100, "rtl8125", 3));
    registry.release_all();
    assert_eq!(registry.domain(0x501, "ahci"), None);
    assert_eq!(registry.domain(0x100, "rtl8125"), None);
    assert!(!registry.register(0x100, "rtl8125", 3));
}

#[test]
fn the_contained_rtl8125_declaration_needs_a_domain_and_no_witness() {
    assert_eq!(RTL8125_CONTAINED.owner, "rtl8125");
    assert_eq!(
        admit(Profile::Recording, &RTL8125_CONTAINED, None),
        Err(Refusal::WitnessMissing)
    );
    let vm = crate::rtl8125_pci::Envelope::for_test(
        true,
        crate::rtl8125_pci::KVM_SIGNATURE,
        crate::rtl8125_pci::Q35_HOST_BRIDGE,
    );
    let token = crate::rtl8125_pci::containment(&vm).ok();
    assert_eq!(
        admit(Profile::Recording, &RTL8125_CONTAINED, token.as_ref()),
        Err(Refusal::WitnessMissing)
    );
    assert_eq!(
        admit(Profile::Enforced, &RTL8125_CONTAINED, None),
        Err(Refusal::Profile)
    );
    assert_eq!(
        effective_state(RTL8125_CONTAINED.state, None),
        State::Unavailable(Unavailability::NoBackend)
    );
    assert_eq!(
        effective_state(RTL8125_CONTAINED.state, Some(3)),
        State::Contained { unit: 0, domain: 3 }
    );
    // The VM declaration is never upgraded, so a VM witness cannot stand in.
    assert_eq!(effective_state(RTL8125.state, Some(3)), RTL8125.state);
}

#[test]
fn a_contained_declaration_with_a_live_domain_arms_only_when_enforced() {
    let live = Declaration {
        state: effective_state(RTL8125_CONTAINED.state, Some(3)),
        ..RTL8125_CONTAINED
    };
    assert_eq!(admit(Profile::Enforced, &live, None), Ok(()));
    assert_eq!(
        admit(Profile::Recording, &live, None),
        Err(Refusal::WitnessMissing)
    );
}
