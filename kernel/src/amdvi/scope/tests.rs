extern crate std;
use super::*;
use crate::amdvi::DeviceRefusal;
use crate::mcfg::{ExtError, ExtFacts};

const QUIET: ExtFacts = ExtFacts {
    ats_enabled: false,
    pasid_enabled: false,
    pri_enabled: false,
    sriov_vfs_enabled: false,
};

const DUMMY: SiblingFacts = SiblingFacts {
    function: 0,
    vendor: 0x1022,
    device: 0x145a,
    class: 0x13_0000,
    bus_master: false,
    decode: false,
    bars_zero: true,
};

fn ahci_shaped() -> ScopeFacts {
    ScopeFacts {
        vendor: 0x1022,
        device: 0x7901,
        subsystem: 0x7901_1022,
        class: 0x01_0601,
        revision: 0x81,
        header_type: 0x80,
        bus: 5,
        express_type: Some(EXPRESS_ENDPOINT),
        phantom_supported: 0,
        phantom_enabled: false,
        upstream: Some(UpstreamPort {
            express_type: Some(EXPRESS_ROOT_PORT),
            secondary: 5,
            subordinate: 5,
        }),
        peers: false,
        siblings: [Some(DUMMY), None, None, None, None, None, None],
        extended: Ok(QUIET),
    }
}

fn nic_shaped() -> ScopeFacts {
    ScopeFacts {
        vendor: 0x10ec,
        device: 0x8125,
        subsystem: 0,
        class: 0x02_0000,
        revision: 0x05,
        header_type: 0,
        bus: 1,
        upstream: Some(UpstreamPort {
            express_type: Some(EXPRESS_ROOT_PORT),
            secondary: 1,
            subordinate: 1,
        }),
        siblings: [None; 7],
        ..ahci_shaped()
    }
}

const OWN: Result<(), DeviceRefusal> = Ok(());

fn ahci(f: impl FnOnce(&mut ScopeFacts)) -> Result<Scope, ScopeRefusal> {
    let mut facts = ahci_shaped();
    f(&mut facts);
    admit_scope(Driver::Ahci, &facts, OWN)
}

fn nic(f: impl FnOnce(&mut ScopeFacts)) -> Result<Scope, ScopeRefusal> {
    let mut facts = nic_shaped();
    f(&mut facts);
    admit_scope(Driver::Rtl8125, &facts, OWN)
}

#[test]
fn the_expected_shapes_are_admitted() {
    let scope = ahci(|_| {}).unwrap();
    assert!(scope.sibling_accepted());
    assert!(!nic(|_| {}).unwrap().sibling_accepted());
}

#[test]
fn identity_is_per_driver() {
    assert_eq!(ahci(|f| f.device = 0x7904), Err(ScopeRefusal::Identity));
    assert_eq!(ahci(|f| f.vendor = 0x8086), Err(ScopeRefusal::Identity));
    assert_eq!(ahci(|f| f.class = 0x01_0400), Err(ScopeRefusal::Identity));
    assert_eq!(nic(|f| f.device = 0x8168), Err(ScopeRefusal::Identity));
    assert_eq!(
        admit_scope(Driver::Ahci, &nic_shaped(), OWN),
        Err(ScopeRefusal::Identity)
    );
}

#[test]
fn rtl8125_needs_revision_05() {
    assert_eq!(nic(|f| f.revision = 0x04), Err(ScopeRefusal::Revision));
}

#[test]
fn a_bridge_header_refuses() {
    assert_eq!(ahci(|f| f.header_type = 0x81), Err(ScopeRefusal::Header));
    assert_eq!(nic(|f| f.header_type = 0x01), Err(ScopeRefusal::Header));
}

#[test]
fn only_an_endpoint_is_admitted() {
    assert_eq!(
        ahci(|f| f.express_type = Some(9)),
        Err(ScopeRefusal::PortType)
    );
    assert_eq!(ahci(|f| f.express_type = None), Err(ScopeRefusal::PortType));
}

#[test]
fn phantom_functions_refuse() {
    assert_eq!(
        ahci(|f| f.phantom_supported = 1),
        Err(ScopeRefusal::Requester)
    );
    assert_eq!(
        ahci(|f| f.phantom_enabled = true),
        Err(ScopeRefusal::Requester)
    );
}

#[test]
fn the_path_must_be_one_root_port_covering_only_this_bus() {
    assert_eq!(ahci(|f| f.upstream = None), Err(ScopeRefusal::Path));
    let port = |express_type, secondary, subordinate| {
        Some(UpstreamPort {
            express_type,
            secondary,
            subordinate,
        })
    };
    assert_eq!(
        ahci(|f| f.upstream = port(Some(6), 5, 5)),
        Err(ScopeRefusal::Path)
    );
    assert_eq!(
        ahci(|f| f.upstream = port(None, 5, 5)),
        Err(ScopeRefusal::Path)
    );
    assert_eq!(
        ahci(|f| f.upstream = port(Some(EXPRESS_ROOT_PORT), 4, 5)),
        Err(ScopeRefusal::Path)
    );
    assert_eq!(
        ahci(|f| f.upstream = port(Some(EXPRESS_ROOT_PORT), 5, 6)),
        Err(ScopeRefusal::Path)
    );
}

#[test]
fn another_device_on_the_bus_refuses() {
    assert_eq!(ahci(|f| f.peers = true), Err(ScopeRefusal::Peers));
}

#[test]
fn translated_traffic_refuses() {
    for set in [
        (|e: &mut ExtFacts| e.ats_enabled = true) as fn(&mut ExtFacts),
        |e| e.pasid_enabled = true,
        |e| e.pri_enabled = true,
    ] {
        let mut ext = QUIET;
        set(&mut ext);
        assert_eq!(
            ahci(|f| f.extended = Ok(ext)),
            Err(ScopeRefusal::Translated)
        );
    }
}

#[test]
fn enabled_virtual_functions_refuse() {
    let ext = ExtFacts {
        sriov_vfs_enabled: true,
        ..QUIET
    };
    assert_eq!(ahci(|f| f.extended = Ok(ext)), Err(ScopeRefusal::Sriov));
}

#[test]
fn unreadable_extended_space_refuses() {
    for error in [ExtError::Unreadable, ExtError::Malformed] {
        assert_eq!(
            ahci(|f| f.extended = Err(error)),
            Err(ScopeRefusal::ExtendedUnreadable)
        );
    }
}

#[test]
fn an_ivrs_refusal_refuses() {
    assert_eq!(
        admit_scope(Driver::Ahci, &ahci_shaped(), Err(DeviceRefusal::Iommu)),
        Err(ScopeRefusal::Ivrs(DeviceRefusal::Iommu))
    );
}

fn with_sibling(change: impl FnOnce(&mut SiblingFacts)) -> Result<Scope, ScopeRefusal> {
    let mut sibling = DUMMY;
    change(&mut sibling);
    ahci(|f| f.siblings[0] = Some(sibling))
}

#[test]
fn the_ahci_sibling_must_be_the_quiet_dummy_function() {
    assert_eq!(
        with_sibling(|s| s.device = 0x1234),
        Err(ScopeRefusal::Sibling)
    );
    assert_eq!(
        with_sibling(|s| s.class = 0x01_0601),
        Err(ScopeRefusal::Sibling)
    );
    assert_eq!(
        with_sibling(|s| s.bus_master = true),
        Err(ScopeRefusal::Sibling)
    );
    assert_eq!(
        with_sibling(|s| s.decode = true),
        Err(ScopeRefusal::Sibling)
    );
    assert_eq!(
        with_sibling(|s| s.bars_zero = false),
        Err(ScopeRefusal::Sibling)
    );
}

#[test]
fn a_second_sibling_of_any_kind_is_judged_too() {
    let mut other = DUMMY;
    other.function = 2;
    other.device = 0x9999;
    assert_eq!(
        ahci(|f| f.siblings[1] = Some(other)),
        Err(ScopeRefusal::Sibling)
    );
}

#[test]
fn rtl8125_must_be_alone_on_its_device() {
    assert_eq!(
        nic(|f| f.siblings[0] = Some(DUMMY)),
        Err(ScopeRefusal::Sibling)
    );
    assert_eq!(nic(|f| f.header_type = 0x80), Err(ScopeRefusal::Sibling));
}

#[test]
fn ordering_bits_refuse_separately_from_scope() {
    assert_eq!(admit_ordering(0x2000), Ok(()));
    assert_eq!(admit_ordering(1 << 4), Err(ScopeRefusal::Ordering));
    assert_eq!(admit_ordering(1 << 11), Err(ScopeRefusal::Ordering));
}

#[test]
fn scope_ignores_ordering_so_a_correction_is_not_a_change() {
    assert_eq!(ahci(|_| {}), ahci(|_| {}));
    assert_ne!(ahci(|_| {}).unwrap(), nic(|_| {}).unwrap());
}

fn qemu_shaped() -> ScopeFacts {
    ScopeFacts {
        vendor: 0x8086,
        device: 0x2922,
        subsystem: 0x1100_1af4,
        class: 0x01_0601,
        revision: 2,
        header_type: 0,
        bus: 0,
        express_type: None,
        upstream: None,
        peers: true,
        siblings: [None; 7],
        extended: Err(ExtError::Unreadable),
        ..ahci_shaped()
    }
}

#[cfg(not(feature = "contain-qemu-fixture"))]
#[test]
fn without_the_fixture_feature_the_qemu_form_refuses() {
    assert_eq!(
        admit_scope(Driver::Ahci, &qemu_shaped(), OWN),
        Err(ScopeRefusal::Identity)
    );
}

#[cfg(feature = "contain-qemu-fixture")]
#[test]
fn the_fixture_feature_admits_only_the_exact_qemu_form() {
    assert!(admit_scope(Driver::Ahci, &qemu_shaped(), OWN).is_ok());
    let mut wrong = qemu_shaped();
    wrong.subsystem = 0;
    assert_eq!(
        admit_scope(Driver::Ahci, &wrong, OWN),
        Err(ScopeRefusal::Identity)
    );
    let mut off_bus = qemu_shaped();
    off_bus.bus = 1;
    assert_eq!(
        admit_scope(Driver::Ahci, &off_bus, OWN),
        Err(ScopeRefusal::Path)
    );
    assert_eq!(
        admit_scope(Driver::Ahci, &qemu_shaped(), Err(DeviceRefusal::Iommu)),
        Err(ScopeRefusal::Ivrs(DeviceRefusal::Iommu))
    );
}

#[test]
fn the_real_controller_on_bus_zero_never_takes_the_fixture_form() {
    assert_eq!(
        ahci(|f| {
            f.bus = 0;
            f.express_type = None;
            f.upstream = None;
        }),
        Err(ScopeRefusal::PortType)
    );
}

#[test]
fn no_physical_build_carries_the_fixture_feature() {
    let makefile = include_str!("../../../Makefile");
    let recipe = makefile
        .lines()
        .skip_while(|line| !line.starts_with("physical-build:"))
        .nth(1)
        .unwrap();
    assert!(recipe.contains("--features block-read-only"));
    assert!(!recipe.contains("contain-qemu-fixture"));
    let manifest = include_str!("../../../Cargo.toml");
    assert!(
        !manifest
            .lines()
            .any(|l| l.starts_with("default") && l.contains("contain-qemu-fixture"))
    );
}

#[test]
fn custody_steps_run_only_in_order() {
    use CustodyStep::*;
    let mut c = CustodySequence::NEW;
    assert!(!c.advance(Exposed));
    assert!(!c.advance(BusMasterClear));
    for step in [
        Eligible,
        BusMasterClear,
        OrderingChecked,
        SurfaceReady,
        Exposed,
        Admitted,
    ] {
        assert!(c.advance(step), "{step:?}");
    }
    assert!(!c.advance(Eligible));
    assert!(!c.advance(Admitted));
}

#[test]
fn exposure_needs_the_bus_master_clear_first() {
    use CustodyStep::*;
    let mut c = CustodySequence::NEW;
    assert!(c.advance(Eligible));
    assert!(!c.advance(Exposed));
    assert!(!c.exposed());
    assert!(c.advance(BusMasterClear));
    assert!(c.advance(OrderingChecked));
    assert!(c.advance(SurfaceReady));
    assert!(c.advance(Exposed));
    assert!(c.exposed());
}

#[test]
fn the_refusal_path_keeps_only_the_named_exceptions() {
    assert!(refusal_exempt(0x0806, false, false));
    assert!(refusal_exempt(0x0600, false, false));
    assert!(refusal_exempt(0x0300, true, false));
    assert!(refusal_exempt(0x0604, false, true));
    // A bridge that is not above the display is cleared.
    assert!(!refusal_exempt(0x0604, false, false));
    assert!(!refusal_exempt(0x0106, false, false));
    assert!(!refusal_exempt(0x0200, false, false));
}

/// Not a unit test: what the admission code says about a real machine's dumped
/// tables and configuration space. `ABSD_REAL_CONFIG` names a private directory:
/// cfg-BB:DD.F.bin, IVRS.bin, MCFG.bin, efr.txt, counters.txt, and which functions
/// to judge: iommu.txt, display.txt, functions.txt (every function on the machine)
/// and targets.txt (`driver function upstream-port` per line). Nothing from it
/// is committed, and every fact comes from it.
/// Run with `cargo test --lib real_machine -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_machine_tables_and_scope() {
    extern crate std;
    use crate::amdvi::{self, Live};
    use crate::ivrs::{self, Entries, Unit};
    use crate::mcfg;
    use std::boxed::Box;
    use std::println;
    use std::vec::Vec;

    let dir = std::env::var("ABSD_REAL_CONFIG").expect("ABSD_REAL_CONFIG");
    let read_file = |name: &str| std::fs::read(std::format!("{dir}/{name}")).unwrap();
    let cfg = |bdf: &str| read_file(&std::format!("cfg-{bdf}.bin"));
    let d32 = |c: &[u8], at: usize| u32::from_le_bytes([c[at], c[at + 1], c[at + 2], c[at + 3]]);
    let express = |c: &[u8]| -> Option<usize> {
        let mut at = c[0x34] as usize & 0xfc;
        for _ in 0..48 {
            if at < 0x40 {
                return None;
            }
            if c[at] == 0x10 {
                return Some(at);
            }
            at = c[at + 1] as usize & 0xfc;
        }
        None
    };
    let express_type = |c: &[u8]| express(c).map(|at| (d32(c, at) >> 20) as u8 & 0xf);

    let bytes = read_file("IVRS.bin");
    let mut unit: Box<Unit> = Box::new(Unit::EMPTY);
    let mut scratch: Box<Entries> = Box::new(Entries::EMPTY);
    let validation = ivrs::parse(&bytes, &mut unit, &mut scratch);
    println!(
        "IVRS parse: {:?}",
        validation.as_ref().map(|v| v.deviations)
    );
    let validation = validation.unwrap();
    println!(
        "unit devid={:#06x} base={:#x} window={:#x} findings={}",
        unit.devid,
        unit.base,
        unit.window(),
        unit.findings.items().len()
    );
    for finding in unit.findings.items() {
        println!(
            "  finding block={:02x}h field={} {}",
            finding.block,
            finding.field.name(),
            finding.detail
        );
    }
    let text = |name: &str| std::string::String::from_utf8(read_file(name)).unwrap();
    let iommu = cfg(text("iommu.txt").trim());
    let [header_at, ..] = unit.capability_registers().unwrap();
    let efr = u64::from_str_radix(
        std::str::from_utf8(&read_file("efr.txt"))
            .unwrap()
            .trim()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let live = Live {
        cap_header: d32(&iommu, header_at as usize),
        efr,
        counters: read_file("counters.txt")
            .get(..)
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|t| u64::from_str_radix(t.trim().trim_start_matches("0x"), 16).ok()),
    };
    println!(
        "live cap={:#010x} efr={:#x} counters={:x?}",
        live.cap_header, live.efr, live.counters
    );
    println!(
        "admit_table: {:?}",
        amdvi::admit_table(&unit, &validation, &live).map(|a| a.quirked)
    );
    for finding in unit.findings.items() {
        println!(
            "  quirk {:?}",
            amdvi::quirk_for(&unit, finding, &live).map(|q| q.name)
        );
    }
    let regions = mcfg::parse(&read_file("MCFG.bin"));
    println!("MCFG parse ok={}", regions.is_ok());

    let hex2 = |s: &str| u8::from_str_radix(s, 16).unwrap();
    let parts = |bdf: &str| {
        let (b, rest) = bdf.split_once(':').unwrap();
        let (d, f) = rest.split_once('.').unwrap();
        (hex2(b), hex2(d), hex2(f))
    };
    let dev = |bdf: &str| {
        let (b, d, f) = parts(bdf);
        (u16::from(b) << 8) | (u16::from(d) << 3) | u16::from(f)
    };
    let functions = text("functions.txt");
    let functions: Vec<&str> = functions.split_whitespace().collect();
    let facts_of = |bdf: &str, port: &str| -> ScopeFacts {
        let c = cfg(bdf);
        let p = cfg(port);
        let at = express(&c).unwrap();
        let (bus, device, function) = parts(bdf);
        let mut siblings = [None; 7];
        let mut count = 0;
        let mut peers = false;
        for other in &functions {
            let (b, d, f) = parts(other);
            if b != bus {
                continue;
            }
            if d != device {
                peers = true;
            } else if f != function {
                let x = cfg(other);
                siblings[count] = Some(SiblingFacts {
                    function: f,
                    vendor: u16::from_le_bytes([x[0], x[1]]),
                    device: u16::from_le_bytes([x[2], x[3]]),
                    class: d32(&x, 8) >> 8,
                    bus_master: x[4] & 4 != 0,
                    decode: x[4] & 3 != 0,
                    bars_zero: (0..6).all(|n| d32(&x, 0x10 + n * 4) == 0),
                });
                count += 1;
            }
        }
        ScopeFacts {
            vendor: u16::from_le_bytes([c[0], c[1]]),
            device: u16::from_le_bytes([c[2], c[3]]),
            subsystem: d32(&c, 0x2c),
            class: d32(&c, 8) >> 8,
            revision: c[8],
            header_type: c[0x0e],
            bus,
            express_type: express_type(&c),
            phantom_supported: ((d32(&c, at + 4) >> 3) & 3) as u8,
            phantom_enabled: d32(&c, at + 8) & (1 << 9) != 0,
            upstream: Some(UpstreamPort {
                express_type: express_type(&p),
                secondary: p[0x19],
                subordinate: p[0x1a],
            }),
            peers,
            siblings,
            extended: mcfg::extended_facts(|o| d32(&c, o as usize)),
        }
    };
    for line in text("targets.txt").lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let driver = if fields[0] == "ahci" {
            Driver::Ahci
        } else {
            Driver::Rtl8125
        };
        let facts = facts_of(fields[1], fields[2]);
        let verdict = admit_scope(driver, &facts, amdvi::admit_device(&unit, dev(fields[1])));
        println!(
            "{} {}: peers={} scope={:?} devctl-ordering={:?} ext={:?}",
            fields[0],
            fields[1],
            facts.peers,
            verdict.map(|s| s.sibling_accepted()),
            admit_ordering(d32(&cfg(fields[1]), express(&cfg(fields[1])).unwrap() + 8) as u16),
            facts.extended
        );
    }
    let display = text("display.txt");
    let display = display.trim();
    println!(
        "display {display}: ivrs={:?} class={:#08x}",
        amdvi::admit_device(&unit, dev(display)),
        d32(&cfg(display), 8) >> 8
    );
}
