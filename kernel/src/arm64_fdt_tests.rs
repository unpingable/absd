//! Host tests of the ARM64 device-tree reader. The trees are built here, in
//! the shape QEMU virt (the qualified platform) and the Youyeetoo YY3568
//! (RK3568, as U-Boot hands its tree over) have: the same node names,
//! compatibles, `status`, `device_type`, cell sizes and register values, with
//! the nodes the reader must ignore (an ITS child, a GPIO interrupt
//! controller, disabled UARTs). The real compiled trees are not in the
//! repository (their `dt-bindings` inputs are GPL-2.0-only); when
//! `ABSD_ARM64_REAL_DTB_DIR` names a directory holding them, the last tests
//! read the same facts from the real files.
extern crate std;
use super::arm64_fdt::{Gic, Psci, Uart, parse};
use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

const VIRT_UART: (u64, Uart) = (0x0900_0000, Uart::Pl011);
const RK3568_UART2: (u64, Uart) = (0xfe66_0000, Uart::DwApb);
const RK3568_UART3: (u64, Uart) = (0xfe67_0000, Uart::DwApb);

/// A flattened device tree writer: header, empty reservation map,
/// structure block, strings block (specification v17).
#[derive(Default)]
struct Fdt {
    structure: Vec<u8>,
    strings: Vec<u8>,
    names: HashMap<String, u32>,
}
impl Fdt {
    fn be(&mut self, v: u32) {
        self.structure.extend_from_slice(&v.to_be_bytes());
    }
    fn pad(&mut self) {
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
    }
    fn begin(&mut self, name: &str) -> &mut Self {
        self.be(1);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad();
        self
    }
    fn end(&mut self) -> &mut Self {
        self.be(2);
        self
    }
    fn prop(&mut self, name: &str, data: &[u8]) -> &mut Self {
        let offset = match self.names.get(name) {
            Some(offset) => *offset,
            None => {
                let offset = self.strings.len() as u32;
                self.strings.extend_from_slice(name.as_bytes());
                self.strings.push(0);
                self.names.insert(String::from(name), offset);
                offset
            }
        };
        self.be(3);
        self.be(data.len() as u32);
        self.be(offset);
        self.structure.extend_from_slice(data);
        self.pad();
        self
    }
    fn str(&mut self, name: &str, values: &[&str]) -> &mut Self {
        let mut data = Vec::new();
        for value in values {
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        self.prop(name, &data)
    }
    fn u32s(&mut self, name: &str, values: &[u32]) -> &mut Self {
        let data: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
        self.prop(name, &data)
    }
    /// `reg` cells for `#address-cells = <2>`, `#size-cells = <2>`.
    fn reg64(&mut self, pairs: &[(u64, u64)]) -> &mut Self {
        let data: Vec<u8> = pairs
            .iter()
            .flat_map(|(a, s)| [a.to_be_bytes(), s.to_be_bytes()].concat())
            .collect();
        self.prop("reg", &data)
    }
    fn finish(mut self) -> Vec<u8> {
        self.be(9);
        let header = 40usize;
        let rsvmap = header;
        let structure = rsvmap + 16;
        let strings = structure + self.structure.len();
        let total = strings + self.strings.len();
        let mut out = Vec::new();
        for v in [
            0xd00d_feedu32,
            total as u32,
            structure as u32,
            strings as u32,
            rsvmap as u32,
            17,
            16,
            0,
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.structure);
        out.extend_from_slice(&self.strings);
        out
    }
}

struct VirtShape {
    gic_compatible: &'static str,
    redistributor_regions: u32,
    bootargs: &'static str,
}
impl Default for VirtShape {
    fn default() -> Self {
        Self {
            gic_compatible: "arm,gic-v3",
            redistributor_regions: 1,
            bootargs: "",
        }
    }
}
/// QEMU `virt-8.2,gic-version=3`, one vCPU, 512 MiB, as the machine dumps it
/// (node names, PL011, 32 virtio transports counted down, psci by hvc).
fn virt(shape: VirtShape) -> Vec<u8> {
    let mut f = Fdt::default();
    f.begin("")
        .u32s("#address-cells", &[2])
        .u32s("#size-cells", &[2])
        .str("compatible", &["linux,dummy-virt"]);
    f.begin("psci")
        .str("compatible", &["arm,psci-1.0", "arm,psci-0.2", "arm,psci"])
        .str("method", &["hvc"])
        .end();
    f.begin("memory@40000000")
        .str("device_type", &["memory"])
        .reg64(&[(0x4000_0000, 0x2000_0000)])
        .end();
    f.begin("cpus")
        .u32s("#address-cells", &[1])
        .u32s("#size-cells", &[0]);
    f.begin("cpu@0")
        .str("device_type", &["cpu"])
        .str("compatible", &["arm,cortex-a72"])
        .str("enable-method", &["psci"])
        .u32s("reg", &[0])
        .end();
    f.end();
    f.begin("intc@8000000")
        .str("compatible", &[shape.gic_compatible])
        .u32s("#redistributor-regions", &[shape.redistributor_regions])
        .prop("interrupt-controller", &[])
        .reg64(&[(0x0800_0000, 0x1_0000), (0x080a_0000, 0xf6_0000)]);
    f.begin("its@8080000")
        .str("compatible", &["arm,gic-v3-its"])
        .reg64(&[(0x0808_0000, 0x2_0000)])
        .end();
    f.end();
    f.begin("pl011@9000000")
        .str("compatible", &["arm,pl011", "arm,primecell"])
        .reg64(&[(VIRT_UART.0, 0x1000)])
        .end();
    f.begin("pl031@9010000")
        .str("compatible", &["arm,pl031", "arm,primecell"])
        .reg64(&[(0x0901_0000, 0x1000)])
        .end();
    for i in (0..32u64).rev() {
        let base = 0x0a00_0000 + i * 0x200;
        f.begin(&std::format!("virtio_mmio@{base:x}"))
            .str("compatible", &["virtio,mmio"])
            .reg64(&[(base, 0x200)])
            .end();
    }
    f.begin("chosen").str("bootargs", &[shape.bootargs]).end();
    f.end();
    f.finish()
}

struct Rk3568Shape {
    memory: Option<&'static [(u64, u64)]>,
    uart3_enabled: bool,
    cpu_ids: [u64; 4],
    /// uart2's `compatible`, `reg-shift` and `reg-io-width` (absent: None).
    uart2_compatible: &'static [&'static str],
    uart2_layout: (Option<u32>, Option<u32>),
}
impl Default for Rk3568Shape {
    fn default() -> Self {
        Self {
            memory: Some(&[(0x20_0000, 0xefe0_0000), (0x1_0000_0000, 0x1000_0000)]),
            uart3_enabled: false,
            cpu_ids: [0x000, 0x100, 0x200, 0x300],
            uart2_compatible: &["rockchip,rk3568-uart", "snps,dw-apb-uart"],
            uart2_layout: (Some(2), Some(4)),
        }
    }
}
/// The YY3568 tree as U-Boot passes it: Rockchip node names, the GIC-600 at
/// 0xfd400000 with its ITS child, a GPIO block that is an interrupt
/// controller too, ten DW-APB UARTs of which uart0 comes first and only
/// uart2 is enabled, Aff1 CPU ids, psci by smc, and U-Boot's `/memory`
/// without unit address.
fn rk3568(shape: Rk3568Shape) -> Vec<u8> {
    let mut f = Fdt::default();
    f.begin("")
        .u32s("#address-cells", &[2])
        .u32s("#size-cells", &[2])
        .str("compatible", &["youyeetoo,yy3568", "rockchip,rk3568"])
        .str("model", &["Youyeetoo YY3568"]);
    f.begin("cpus")
        .u32s("#address-cells", &[2])
        .u32s("#size-cells", &[0]);
    for id in shape.cpu_ids {
        f.begin(&std::format!("cpu@{id:x}"))
            .str("device_type", &["cpu"])
            .str("compatible", &["arm,cortex-a55"])
            .str("enable-method", &["psci"])
            .u32s("reg", &[(id >> 32) as u32, id as u32])
            .end();
    }
    f.end();
    f.begin("psci")
        .str("compatible", &["arm,psci-1.0"])
        .str("method", &["smc"])
        .end();
    f.begin("timer")
        .str("compatible", &["arm,armv8-timer"])
        .u32s(
            "interrupts",
            &[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4, 1, 12, 4],
        )
        .end();
    f.begin("interrupt-controller@fd400000")
        .str("compatible", &["arm,gic-v3"])
        .reg64(&[(0xfd40_0000, 0x1_0000), (0xfd46_0000, 0x8_0000)])
        .prop("interrupt-controller", &[])
        .u32s("#interrupt-cells", &[3]);
    f.begin("msi-controller@fd440000")
        .str("compatible", &["arm,gic-v3-its"])
        .reg64(&[(0xfd44_0000, 0x2_0000)])
        .end();
    f.end();
    // Not a GIC-shaped name: the `interrupt-controller` property alone must
    // leave it ignored (the refusal keys on `intc@` / `interrupt-controller@`).
    f.begin("gpio@fdd60000")
        .str("compatible", &["rockchip,gpio-bank"])
        .reg64(&[(0xfdd6_0000, 0x100)])
        .prop("interrupt-controller", &[])
        .end();
    let uarts: [(u64, bool); 10] = [
        (0xfdd5_0000, false),
        (0xfe65_0000, false),
        (RK3568_UART2.0, true),
        (RK3568_UART3.0, shape.uart3_enabled),
        (0xfe68_0000, false),
        (0xfe69_0000, false),
        (0xfe6a_0000, false),
        (0xfe6b_0000, false),
        (0xfe6c_0000, false),
        (0xfe6d_0000, false),
    ];
    for (base, enabled) in uarts {
        let (compatible, layout) = if base == RK3568_UART2.0 {
            (shape.uart2_compatible, shape.uart2_layout)
        } else {
            (
                &["rockchip,rk3568-uart", "snps,dw-apb-uart"][..],
                (Some(2), Some(4)),
            )
        };
        f.begin(&std::format!("serial@{base:x}"))
            .str("compatible", compatible)
            .reg64(&[(base, 0x100)]);
        if let Some(shift) = layout.0 {
            f.u32s("reg-shift", &[shift]);
        }
        if let Some(width) = layout.1 {
            f.u32s("reg-io-width", &[width]);
        }
        f.str("status", &[if enabled { "okay" } else { "disabled" }])
            .end();
    }
    f.begin("mmc@fe310000")
        .str("compatible", &["rockchip,rk3568-dwcmshc"])
        .reg64(&[(0xfe31_0000, 0x1_0000)])
        .str("status", &["okay"])
        .end();
    if let Some(banks) = shape.memory {
        f.begin("memory")
            .str("device_type", &["memory"])
            .reg64(banks)
            .end();
    }
    f.begin("chosen")
        .str("bootargs", &["console=ttyS2,1500000"])
        .end();
    f.end();
    f.finish()
}

#[test]
fn qemu_virt_gicv3_reads_as_before() {
    let board = parse(&virt(VirtShape::default()), VIRT_UART).unwrap();
    assert_eq!(board.gic, Some(Gic::V3));
    assert_eq!(board.gicd, 0x0800_0000);
    assert_eq!(board.gicc, 0x080a_0000);
    assert_eq!(board.gic_region_bytes, 0xf6_0000);
    assert_eq!((board.uart, board.uart_kind), VIRT_UART);
    assert_eq!(board.bank_count, 1);
    assert_eq!(board.banks[0], (0x4000_0000, 512 << 20));
    assert_eq!((board.cpu_count, board.cpu_shift), (1, 0));
    assert_eq!(board.cpus[0], 0);
    assert_eq!(board.psci, Some(Psci::Hvc));
    assert!(board.psci_02);
    assert_eq!(board.virtio_count, 32);
    assert!(board.virtio[..32].contains(&0x0a00_0000));
    assert!(
        board.virtio[..32]
            .iter()
            .all(|base| (0x0a00_0000..0x0a00_4000).contains(base))
    );
    assert_eq!(board.smp_request, 0);
    assert!(!board.reset && !board.early_publication);
    assert_eq!(
        board.placement((0x4008_0000, 0x4010_0000), (0x4000_0000, 0x4000_2000)),
        Ok((0x4000_0000, 512 << 20))
    );
    assert_eq!(
        board.placement((0x4008_0000, 0x4010_0000), (0x6000_0000, 0x6000_2000)),
        Err("FDT device tree outside every memory bank")
    );
}

#[test]
fn qemu_virt_bootargs_still_read() {
    let board = parse(
        &virt(VirtShape {
            bootargs: "absd-arm-smp=2 absd-arm-control=early-publication",
            ..VirtShape::default()
        }),
        VIRT_UART,
    )
    .unwrap();
    assert_eq!(board.smp_request, 2);
    assert!(board.early_publication);
}

#[test]
fn qemu_virt_controls_are_refused_by_name() {
    let bogus = virt(VirtShape {
        gic_compatible: "arm,gic-v9",
        ..VirtShape::default()
    });
    assert_eq!(
        parse(&bogus, VIRT_UART).err(),
        Some("FDT unsupported GIC version")
    );
    let two = virt(VirtShape {
        redistributor_regions: 2,
        ..VirtShape::default()
    });
    assert_eq!(
        parse(&two, VIRT_UART).err(),
        Some("FDT unsupported GIC redistributor regions")
    );
}

#[test]
fn rk3568_without_a_memory_node_is_a_missing_platform() {
    let tree = rk3568(Rk3568Shape {
        memory: None,
        ..Rk3568Shape::default()
    });
    assert_eq!(
        parse(&tree, RK3568_UART2).err(),
        Some("FDT required platform missing")
    );
}

#[test]
fn rk3568_as_uboot_passes_it() {
    let board = parse(&rk3568(Rk3568Shape::default()), RK3568_UART2).unwrap();
    assert_eq!(board.gic, Some(Gic::V3));
    assert_eq!(board.gicd, 0xfd40_0000);
    assert_eq!(board.gicc, 0xfd46_0000);
    assert_eq!(board.gic_region_bytes, 0x8_0000);
    assert_eq!((board.uart, board.uart_kind), RK3568_UART2);
    assert_eq!(board.bank_count, 2);
    assert_eq!(board.banks[0], (0x20_0000, 0xefe0_0000));
    assert_eq!(board.banks[1], (0x1_0000_0000, 0x1000_0000));
    assert_eq!((board.cpu_count, board.cpu_shift), (4, 8));
    assert_eq!(&board.cpus[..4], &[0x000, 0x100, 0x200, 0x300]);
    assert_eq!(board.psci, Some(Psci::Smc));
    assert!(board.psci_02);
    assert_eq!(board.virtio_count, 0);
    assert_eq!(board.smp_request, 0);
    // The image at its link address with the tree high in bank 0, where
    // U-Boot's LMB relocation puts it on a 4 GiB unit.
    assert_eq!(
        board.placement((0x4008_0000, 0x4010_0000), (0xef00_0000, 0xef01_0000)),
        Ok((0x20_0000, 0xefe0_0000))
    );
    assert_eq!(
        board.placement((0x4008_0000, 0x4010_0000), (0xf800_0000, 0xf801_0000)),
        Err("FDT device tree outside every memory bank")
    );
    assert_eq!(
        board.placement((0xefff_f000, 0xf000_1000), (0x4000_0000, 0x4000_2000)),
        Err("FDT kernel image outside every memory bank")
    );
}

#[test]
fn rk3568_tree_is_refused_by_a_build_whose_early_console_it_does_not_enable() {
    // A virt build (PL011 early console) must not silently move the console.
    assert_eq!(
        parse(&rk3568(Rk3568Shape::default()), VIRT_UART).err(),
        Some("FDT console UART is not the early console")
    );
}

#[test]
fn two_enabled_uarts_need_the_early_console_among_them() {
    let tree = rk3568(Rk3568Shape {
        uart3_enabled: true,
        ..Rk3568Shape::default()
    });
    assert_eq!(
        parse(&tree, VIRT_UART).err(),
        Some("FDT console UART is not the early console")
    );
    assert_eq!(parse(&tree, RK3568_UART2).unwrap().uart, RK3568_UART2.0);
    assert_eq!(parse(&tree, RK3568_UART3).unwrap().uart, RK3568_UART3.0);
}

#[test]
fn mixed_cpu_numbering_is_refused() {
    let tree = rk3568(Rk3568Shape {
        cpu_ids: [0x000, 0x001, 0x200, 0x300],
        ..Rk3568Shape::default()
    });
    assert_eq!(
        parse(&tree, RK3568_UART2).err(),
        Some("FDT CPU affinity topology")
    );
}

/// A header word of a built tree (offsets per the specification).
fn header(tree: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(tree[offset..offset + 4].try_into().unwrap())
}
fn set_header(tree: &mut [u8], offset: usize, value: u32) {
    tree[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
const SIZE_DT_STRUCT: usize = 36;

#[test]
fn a_structure_block_cut_short_is_refused() {
    // Every token, including FDT_END, must lie inside the declared structure
    // block, not merely inside the blob.
    for (tree, early) in [
        (virt(VirtShape::default()), VIRT_UART),
        (rk3568(Rk3568Shape::default()), RK3568_UART2),
    ] {
        assert!(parse(&tree, early).is_ok());
        let declared = header(&tree, SIZE_DT_STRUCT);
        for cut in 1..=12 {
            let mut short = tree.clone();
            set_header(&mut short, SIZE_DT_STRUCT, declared - cut);
            assert!(
                parse(&short, early).is_err(),
                "size_dt_struct reduced by {cut} accepted"
            );
        }
    }
}

#[test]
fn a_misaligned_or_unsupported_header_is_refused() {
    // The structure block moved one byte (every offset and size kept
    // consistent): the specification requires it 4-byte aligned.
    let tree = virt(VirtShape::default());
    let structure = header(&tree, 8) as usize;
    let mut moved = tree[..structure].to_vec();
    moved.push(0);
    moved.extend_from_slice(&tree[structure..]);
    for offset in [4, 8, 12] {
        let value = header(&moved, offset);
        set_header(&mut moved, offset, value + 1);
    }
    assert_eq!(
        parse(&moved, VIRT_UART).err(),
        Some("FDT structure alignment")
    );
    // A version before 17 has no size_dt_struct; a last compatible version
    // after 17 is a format this reader does not know.
    let mut old = tree.clone();
    set_header(&mut old, 20, 16);
    assert_eq!(parse(&old, VIRT_UART).err(), Some("FDT version"));
    let mut new = tree.clone();
    set_header(&mut new, 24, 18);
    assert_eq!(parse(&new, VIRT_UART).err(), Some("FDT version"));
}

#[test]
fn the_early_console_model_must_match() {
    // The base matches but the model does not: transmitting with the wrong
    // status-register semantics is refused, not attempted.
    assert_eq!(
        parse(&virt(VirtShape::default()), (VIRT_UART.0, Uart::DwApb)).err(),
        Some("FDT console UART model is not the early console's")
    );
    assert_eq!(
        parse(
            &rk3568(Rk3568Shape::default()),
            (RK3568_UART2.0, Uart::Pl011)
        )
        .err(),
        Some("FDT console UART model is not the early console's")
    );
    let pl011_at_uart2 = rk3568(Rk3568Shape {
        uart2_compatible: &["arm,pl011", "arm,primecell"],
        ..Rk3568Shape::default()
    });
    assert_eq!(
        parse(&pl011_at_uart2, RK3568_UART2).err(),
        Some("FDT console UART model is not the early console's")
    );
}

#[test]
fn the_dw_apb_console_register_layout_must_be_the_transmitters() {
    for layout in [
        (Some(0), Some(4)),
        (Some(2), Some(1)),
        (None, Some(4)),
        (Some(2), None),
        (None, None),
    ] {
        let tree = rk3568(Rk3568Shape {
            uart2_layout: layout,
            ..Rk3568Shape::default()
        });
        assert_eq!(
            parse(&tree, RK3568_UART2).err(),
            Some("FDT console UART register layout unsupported"),
            "layout {layout:?}"
        );
    }
}

#[test]
fn an_overflowing_memory_bank_is_refused() {
    // In the bank the kernel would use and in an additional bank.
    for banks in [
        &[(0xffff_ffff_ffff_f000u64, 0x2000u64)][..],
        &[(0xffff_ffff_ffff_f000, 0x1000)][..],
        &[(0x20_0000, 0xefe0_0000), (0xffff_ffff_ffff_f000, 0x2000)][..],
    ] {
        let tree = rk3568(Rk3568Shape {
            memory: Some(banks),
            ..Rk3568Shape::default()
        });
        assert_eq!(
            parse(&tree, RK3568_UART2).err(),
            Some("FDT RAM range overflow"),
            "banks {banks:?}"
        );
    }
    // The highest bank that ends exactly at the top of the address space
    // less one page is still a range.
    let top = rk3568(Rk3568Shape {
        memory: Some(&[(0x20_0000, 0xefe0_0000), (0xffff_ffff_ffff_e000, 0x1000)]),
        ..Rk3568Shape::default()
    });
    assert_eq!(parse(&top, RK3568_UART2).unwrap().bank_count, 2);
}

/// The real trees, when present (the lane registry holds them; see
/// docs/arm64-first-light/README.md).
/// `make arm64-fdt-real-test` runs these with `--nocapture`, so the line
/// printed here is the evidence they read a real file rather than skipped.
fn real(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var("ABSD_ARM64_REAL_DTB_DIR").ok()?;
    let bytes = std::fs::read(std::format!("{dir}/{name}")).expect("real device tree present");
    std::println!("REAL TREE {name}: {} bytes read from {dir}", bytes.len());
    Some(bytes)
}

#[test]
fn real_qemu_virt_tree_matches_the_shape() {
    let Some(tree) = real("virt-gic3.dtb") else {
        return;
    };
    let mut actual = parse(&tree, VIRT_UART).unwrap();
    let mut shaped = parse(&virt(VirtShape::default()), VIRT_UART).unwrap();
    // QEMU's node order for the transports is its own; the set is what matters.
    actual.virtio[..actual.virtio_count].sort_unstable();
    shaped.virtio[..shaped.virtio_count].sort_unstable();
    shaped.dtb_bytes = actual.dtb_bytes;
    assert_eq!(std::format!("{actual:?}"), std::format!("{shaped:?}"));
    let mut short = tree.clone();
    set_header(
        &mut short,
        SIZE_DT_STRUCT,
        header(&tree, SIZE_DT_STRUCT) - 1,
    );
    assert!(parse(&short, VIRT_UART).is_err());
    let bogus = real("virt-gic3-bogus-compatible.dtb").unwrap();
    assert_eq!(
        parse(&bogus, VIRT_UART).err(),
        Some("FDT unsupported GIC version")
    );
    let two = real("virt-gic3-two-regions.dtb").unwrap();
    assert_eq!(
        parse(&two, VIRT_UART).err(),
        Some("FDT unsupported GIC redistributor regions")
    );
}

#[test]
fn real_yy3568_trees_match_the_shape() {
    let Some(bare) = real("rk3568-yy3568.dtb") else {
        return;
    };
    assert_eq!(
        parse(&bare, RK3568_UART2).err(),
        Some("FDT required platform missing")
    );
    let uboot = real("rk3568-yy3568-uboot.dtb").unwrap();
    let actual = parse(&uboot, RK3568_UART2).unwrap();
    let mut shaped = parse(&rk3568(Rk3568Shape::default()), RK3568_UART2).unwrap();
    shaped.dtb_bytes = actual.dtb_bytes;
    assert_eq!(std::format!("{actual:?}"), std::format!("{shaped:?}"));
    let mut short = uboot.clone();
    set_header(
        &mut short,
        SIZE_DT_STRUCT,
        header(&uboot, SIZE_DT_STRUCT) - 1,
    );
    assert!(parse(&short, RK3568_UART2).is_err());
    assert_eq!(
        parse(&uboot, VIRT_UART).err(),
        Some("FDT console UART is not the early console")
    );
    let two = real("rk3568-yy3568-two-uarts.dtb").unwrap();
    assert_eq!(
        parse(&two, VIRT_UART).err(),
        Some("FDT console UART is not the early console")
    );
    assert_eq!(parse(&two, RK3568_UART2).unwrap().uart, RK3568_UART2.0);
}
