//! Bounded device-tree reader for the ARM64 port: QEMU `virt` and the RK3568
//! class of boards (one GIC, one console UART, up to four memory banks, up
//! to four CPUs). Devices are found by `compatible` and `device_type`, not by
//! node name, because U-Boot and board trees name them differently. Not a
//! general hardware framework.
/// The interrupt controller the tree names: GICv2 (`arm,cortex-a15-gic`,
/// a memory-mapped CPU interface) or GICv3 (`arm,gic-v3`, redistributors
/// and a system-register CPU interface). Anything else is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gic {
    V2,
    V3,
}
/// How PSCI is reached: `hvc` (QEMU virt without EL2 firmware) or `smc`
/// (EL3 firmware, or QEMU virt with `virtualization=on`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Psci {
    Hvc,
    Smc,
}
/// The console UART's register model: PL011 (`arm,pl011`, QEMU virt) or the
/// DesignWare APB 16550 (`snps,dw-apb-uart`, Rockchip: 32-bit registers four
/// bytes apart).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uart {
    Pl011,
    DwApb,
}
pub const MAX_BANKS: usize = 4;
#[derive(Debug)]
pub struct Board {
    /// CPU affinities as MPIDR encodes them, sorted: `0,1,2,3` on QEMU virt
    /// (Aff0), `0x000,0x100,0x200,0x300` on RK3568 (Aff1).
    pub cpus: [u64; 4],
    pub cpu_count: usize,
    /// 0 when CPU `i` has affinity `i`, 8 when it has `i << 8`.
    pub cpu_shift: u32,
    pub smp_request: usize,
    pub early_publication: bool,
    pub reset: bool,
    pub virtio: [u64; 32],
    pub virtio_count: usize,
    /// Every `(base, bytes)` the memory nodes report, in tree order.
    pub banks: [(u64, u64); MAX_BANKS],
    pub bank_count: usize,
    pub uart: u64,
    pub uart_kind: Uart,
    pub gicd: u64,
    /// The second `reg` region: the CPU interface (v2) or the one
    /// redistributor region (v3), with its size.
    pub gicc: u64,
    pub gic_region_bytes: u64,
    pub gic: Option<Gic>,
    pub psci: Option<Psci>,
    /// The psci node names a PSCI 0.2 or later binding (the function ids
    /// this kernel uses).
    pub psci_02: bool,
    pub dtb_bytes: usize,
}
impl Board {
    /// The bank containing `[start, end)`, if one does.
    pub fn bank_containing(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        self.banks[..self.bank_count]
            .iter()
            .copied()
            .find(|(base, bytes)| {
                start >= *base && base.checked_add(*bytes).is_some_and(|top| end <= top)
            })
    }
    /// The kernel image and the device tree must each lie inside one reported
    /// bank; returns the kernel's bank (the frame allocator's region).
    pub fn placement(
        &self,
        kernel: (u64, u64),
        dtb: (u64, u64),
    ) -> Result<(u64, u64), &'static str> {
        let bank = self
            .bank_containing(kernel.0, kernel.1)
            .ok_or("FDT kernel image outside every memory bank")?;
        self.bank_containing(dtb.0, dtb.1)
            .ok_or("FDT device tree outside every memory bank")?;
        Ok(bank)
    }
}
fn word(b: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        b.get(at..at + 4).ok_or("FDT bounds")?.try_into().unwrap(),
    ))
}
fn quad(b: &[u8], at: usize) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(
        b.get(at..at + 8).ok_or("FDT bounds")?.try_into().unwrap(),
    ))
}
fn cstr(b: &[u8], at: usize) -> Result<&[u8], &'static str> {
    let s = b.get(at..).ok_or("FDT string bounds")?;
    Ok(&s[..s
        .iter()
        .position(|x| *x == 0)
        .ok_or("FDT unterminated string")?])
}
fn names(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
}
/// What one node's properties said, committed when the node ends (the
/// properties of a node come in any order, so nothing is decided earlier).
#[derive(Clone, Copy, Default)]
struct Node {
    /// `reg` as (offset, length) into the blob.
    reg: Option<(usize, usize)>,
    gic: Option<Gic>,
    gic_node: bool,
    redistributor_regions: Option<u32>,
    uart: Option<Uart>,
    /// `reg-shift` and `reg-io-width` (one cell each; any other length
    /// reads as unsupported).
    reg_shift: Option<u32>,
    reg_io_width: Option<u32>,
    memory: bool,
    cpu: bool,
    virtio: bool,
    disabled: bool,
}
const HEADER_BYTES: usize = 40;
/// The next 4-byte boundary after `at`, which must still lie inside the
/// structure block (padding is part of it).
fn pad(at: usize, end: usize) -> Result<usize, &'static str> {
    let next = at.checked_add(3).ok_or("FDT overflow")? & !3;
    if next > end {
        return Err("FDT bounds");
    }
    Ok(next)
}
/// A one-cell property's value; any other length reads as `u32::MAX`, which
/// no check accepts.
fn cell(data: &[u8]) -> u32 {
    match data.try_into() {
        Ok(bytes) => u32::from_be_bytes(bytes),
        Err(_) => u32::MAX,
    }
}
/// `early` is the console the kernel has already printed on: its base and
/// register model.
pub fn parse(b: &[u8], early: (u64, Uart)) -> Result<Board, &'static str> {
    if word(b, 0)? != 0xd00dfeed {
        return Err("FDT magic");
    }
    let size = word(b, 4)? as usize;
    if size < HEADER_BYTES || size > b.len() || size > 2 * 1024 * 1024 {
        return Err("FDT size");
    }
    let b = &b[..size];
    // Version 17 is the first with size_dt_struct; a last compatible version
    // above 17 is a layout this reader does not know.
    if word(b, 20)? < 17 || word(b, 24)? > 17 {
        return Err("FDT version");
    }
    let structure = word(b, 8)? as usize;
    let strings = word(b, 12)? as usize;
    let structure_bytes = word(b, 36)? as usize;
    if !structure.is_multiple_of(4) || !structure_bytes.is_multiple_of(4) {
        return Err("FDT structure alignment");
    }
    if structure < HEADER_BYTES || strings < HEADER_BYTES {
        return Err("FDT structure");
    }
    let end = structure
        .checked_add(structure_bytes)
        .ok_or("FDT overflow")?;
    let string_end = strings
        .checked_add(word(b, 32)? as usize)
        .ok_or("FDT overflow")?;
    let strs = b.get(strings..string_end).ok_or("FDT strings")?;
    if end > b.len() {
        return Err("FDT structure");
    }
    // Every token, property header, property value and padding byte is read
    // from the declared structure block only (offsets stay blob-relative).
    let st = &b[..end];
    let mut board = Board {
        cpus: [0; 4],
        cpu_count: 0,
        cpu_shift: 0,
        smp_request: 0,
        early_publication: false,
        reset: false,
        virtio: [0; 32],
        virtio_count: 0,
        banks: [(0, 0); MAX_BANKS],
        bank_count: 0,
        uart: 0,
        uart_kind: Uart::Pl011,
        gicd: 0,
        gicc: 0,
        gic_region_bytes: 0,
        gic: None,
        psci: None,
        psci_02: false,
        dtb_bytes: size,
    };
    // Each enabled UART: base, model, and whether its register layout is the
    // one the transmitter assumes.
    let mut uarts: [(u64, Uart, bool); 16] = [(0, Uart::Pl011, false); 16];
    let mut uart_count = 0usize;
    let mut at = structure;
    let mut depth = 0usize;
    let mut nodes: [&[u8]; 32] = [b""; 32];
    let mut pending: [Node; 32] = [Node::default(); 32];
    let mut ended = false;
    while at < end {
        let token = word(st, at)?;
        at += 4;
        match token {
            1 => {
                if depth == 32 {
                    return Err("FDT depth");
                }
                let n = cstr(st, at)?;
                nodes[depth] = n;
                pending[depth] = Node::default();
                depth += 1;
                at = pad(at + n.len() + 1, end)?;
            }
            2 => {
                depth = depth.checked_sub(1).ok_or("FDT nesting")?;
                let node = pending[depth];
                let reg = |want: &'static str| -> Result<&[u8], &'static str> {
                    let (offset, len) = node.reg.ok_or(want)?;
                    st.get(offset..offset + len).ok_or("FDT bounds")
                };
                if node.gic_node {
                    if node
                        .redistributor_regions
                        .is_some_and(|regions| regions != 1)
                    {
                        return Err("FDT unsupported GIC redistributor regions");
                    }
                    let data = reg("FDT GIC reg")?;
                    if data.len() < 32 {
                        return Err("FDT GIC reg");
                    }
                    board.gic = node.gic;
                    board.gicd = quad(data, 0)?;
                    board.gicc = quad(data, 16)?;
                    board.gic_region_bytes = quad(data, 24)?;
                }
                if let Some(kind) = node.uart
                    && !node.disabled
                {
                    if uart_count == uarts.len() {
                        return Err("FDT too many enabled UARTs");
                    }
                    let layout = match kind {
                        Uart::Pl011 => true,
                        Uart::DwApb => node.reg_shift == Some(2) && node.reg_io_width == Some(4),
                    };
                    uarts[uart_count] = (quad(reg("FDT UART reg")?, 0)?, kind, layout);
                    uart_count += 1;
                }
                if node.memory {
                    let data = reg("FDT memory reg")?;
                    if data.is_empty() || !data.len().is_multiple_of(16) {
                        return Err("FDT RAM topology");
                    }
                    for entry in 0..data.len() / 16 {
                        if board.bank_count == MAX_BANKS {
                            return Err("FDT too many memory banks");
                        }
                        let bank = (quad(data, entry * 16)?, quad(data, entry * 16 + 8)?);
                        if bank.1 == 0 {
                            return Err("FDT RAM topology");
                        }
                        if bank.0.checked_add(bank.1).is_none() {
                            return Err("FDT RAM range overflow");
                        }
                        board.banks[board.bank_count] = bank;
                        board.bank_count += 1;
                    }
                }
                if node.cpu {
                    if board.cpu_count == 4 {
                        return Err("FDT CPU bound");
                    }
                    let data = reg("FDT CPU reg")?;
                    board.cpus[board.cpu_count] = match data.len() {
                        4 => word(data, 0)? as u64,
                        8 => quad(data, 0)?,
                        _ => return Err("FDT CPU reg"),
                    };
                    board.cpu_count += 1;
                }
                if node.virtio && !node.disabled {
                    if board.virtio_count == 32 {
                        return Err("FDT too many virtio transports");
                    }
                    board.virtio[board.virtio_count] = quad(reg("FDT virtio reg")?, 0)?;
                    board.virtio_count += 1;
                }
            }
            3 => {
                let len = word(st, at)? as usize;
                let name = word(st, at + 4)? as usize;
                at += 8;
                let stop = at.checked_add(len).ok_or("FDT overflow")?;
                let data = st.get(at..stop).ok_or("FDT property")?;
                let offset = at;
                at = pad(stop, end)?;
                let key = cstr(strs, name)?;
                let index = depth.checked_sub(1).ok_or("FDT property outside node")?;
                let node_name = *nodes.get(index).ok_or("FDT depth")?;
                let node = pending.get_mut(index).ok_or("FDT depth")?;
                if depth == 1
                    && (key == b"#address-cells" || key == b"#size-cells")
                    && word(data, 0)? != 2
                {
                    return Err("FDT unsupported root cells");
                }
                if node_name == b"chosen" && key == b"bootargs" {
                    for token in data.split(|c| *c == b' ' || *c == 0) {
                        if token == b"absd-arm-reset=1" {
                            board.reset = true;
                        }
                        if token == b"absd-arm-control=early-publication" {
                            board.early_publication = true;
                        }
                        if token.starts_with(b"absd-arm-smp=") {
                            if board.smp_request != 0 {
                                return Err("FDT duplicate SMP request");
                            }
                            board.smp_request = match token {
                                b"absd-arm-smp=2" => 2,
                                b"absd-arm-smp=4" => 4,
                                _ => return Err("FDT SMP request"),
                            };
                        }
                    }
                }
                if key == b"compatible" {
                    for name in names(data) {
                        match name {
                            b"arm,cortex-a15-gic" => {
                                node.gic_node = true;
                                node.gic = Some(Gic::V2);
                            }
                            b"arm,gic-v3" => {
                                node.gic_node = true;
                                node.gic = Some(Gic::V3);
                            }
                            b"arm,pl011" => node.uart = Some(Uart::Pl011),
                            b"snps,dw-apb-uart" => node.uart = Some(Uart::DwApb),
                            b"virtio,mmio" => node.virtio = true,
                            _ => {}
                        }
                    }
                    // A node that calls itself an interrupt controller with a
                    // GIC-shaped name but no supported model is a refusal, not
                    // a device to ignore: the kernel cannot take interrupts.
                    if !node.gic_node
                        && (node_name.starts_with(b"intc@")
                            || node_name.starts_with(b"interrupt-controller@"))
                    {
                        return Err("FDT unsupported GIC version");
                    }
                    if node_name == b"psci" {
                        board.psci_02 = names(data)
                            .any(|name| name == b"arm,psci-0.2" || name == b"arm,psci-1.0");
                    }
                }
                if key == b"device_type" {
                    node.memory = data == b"memory\0";
                    node.cpu = data == b"cpu\0";
                }
                if key == b"status" {
                    node.disabled = data == b"disabled\0";
                }
                if key == b"reg" {
                    node.reg = Some((offset, len));
                }
                if key == b"reg-shift" {
                    node.reg_shift = Some(cell(data));
                }
                if key == b"reg-io-width" {
                    node.reg_io_width = Some(cell(data));
                }
                if key == b"#redistributor-regions" {
                    node.redistributor_regions = Some(word(data, 0)?);
                }
                if node_name == b"psci" && key == b"method" {
                    board.psci = match data {
                        b"hvc\0" => Some(Psci::Hvc),
                        b"smc\0" => Some(Psci::Smc),
                        _ => return Err("FDT unsupported PSCI method"),
                    };
                }
            }
            4 => {}
            9 => {
                ended = true;
                break;
            }
            _ => return Err("FDT token"),
        }
    }
    if !ended {
        return Err("FDT structure end");
    }
    if depth != 0
        || board.bank_count == 0
        || board.gicd == 0
        || board.gicc == 0
        || board.gic.is_none()
        || board.psci.is_none()
        || !board.psci_02
    {
        return Err("FDT required platform missing");
    }
    // The console is the early console's UART, and the tree must enable it:
    // the kernel has already printed there, and silently moving the console
    // to another UART would look like a hang. No enabled UART at all is a
    // missing platform.
    // Its model and register layout must be the ones the kernel has been
    // transmitting with, not just its address.
    let (uart, kind, layout) = match uarts[..uart_count]
        .iter()
        .find(|(base, _, _)| *base == early.0)
    {
        Some(found) => *found,
        None if uart_count == 0 => return Err("FDT required platform missing"),
        None => return Err("FDT console UART is not the early console"),
    };
    if kind != early.1 {
        return Err("FDT console UART model is not the early console's");
    }
    if !layout {
        return Err("FDT console UART register layout unsupported");
    }
    board.uart = uart;
    board.uart_kind = kind;
    if !matches!(board.cpu_count, 1 | 2 | 4) {
        return Err("FDT CPU topology");
    }
    board.cpus[..board.cpu_count].sort_unstable();
    let ids = &board.cpus[..board.cpu_count];
    board.cpu_shift = if ids.iter().enumerate().all(|(i, id)| *id == i as u64) {
        0
    } else if ids.iter().enumerate().all(|(i, id)| *id == (i as u64) << 8) {
        8
    } else {
        return Err("FDT CPU affinity topology");
    };
    Ok(board)
}
